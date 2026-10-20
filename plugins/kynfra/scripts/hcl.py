"""Parser HCL minimale per i guardrail di kynfra (solo libreria standard).

Estrae da `.tf`, `.tfvars`, `.tf.json` e `.tfvars.json` i blocchi (`resource "tipo" "nome"`, `module`, `provider`,
`terraform`, `backend`, `variable`, `data`, `locals`, `output` e i blocchi annidati), gli attributi e i numeri di riga
(1-based). Le espressioni restano testo (`Attr.raw`, senza commento finale, anche se su più righe); `Attr.literal()`
le valuta solo se sono letterali (stringhe senza interpolazione, numeri, bool, liste, oggetti, heredoc).
`Attr.entries()` espone le voci di primo livello di un oggetto anche quando alcuni valori non sono letterali
(es. `tags = { Project = var.project }`), così le regole possono verificare la presenza delle chiavi.

Scelte di robustezza: il parser non solleva mai eccezioni. I commenti (`#`, `//`, `/* */`) sono sostituiti da spazi
rispettando stringhe e heredoc; dentro le interpolazioni `${}`/`%{}` i commenti sono saltati e sostituiti anch'essi,
quindi offset e righe restano quelli del file originale. Con graffe sbilanciate si restituiscono solo i blocchi di
primo livello chiusi; le `}` in eccesso al primo livello vengono ignorate. Attributi ripetuti: vale l'ultimo. Oltre
`_MAX_DEPTH` livelli (blocchi HCL o valori JSON) il contenuto non è analizzato (in JSON diventa un valore opaco, con
`literal()` None) ma il resto del file sì.

Fail closed: `parse_problems` elenca (riga, messaggio) per ogni punto che `parse` non ha potuto leggere (blocco o
parentesi non chiusi, stringa/heredoc/commento/interpolazione non chiusi, elemento non riconosciuto, JSON non valido,
profondità massima, errore interno). Lista vuota = file compreso per intero; le regole trattano ogni problema come
finding bloccante.

Formato dedotto dall'estensione: JSON solo per `*.tf.json` e `*.tfvars.json`, HCL per tutto il resto.

Regola per `.tf.json` (in JSON blocchi annidati e attributi oggetto non si distinguono):
- le chiavi di primo livello sono tipi di blocco; i livelli di etichetta sono 2 per `resource`/`data`, 1 per
  `module`/`provider`/`variable`/`output`/`check`, 0 per `terraform`/`locals`/`moved`/`import`/`removed`; a ogni
  livello (etichetta o corpo) una lista di oggetti equivale a più oggetti dello stesso livello (es. provider con alias,
  `{"resource": [{"aws_s3_bucket": {...}}]}`);
- nel corpo di un blocco ogni chiave diventa un attributo (`literal()` restituisce dict/list così come sono);
  in più, se il valore è un oggetto o una lista di oggetti, viene esposto anche come blocco annidato senza etichette
  (`default_tags`, `ingress`, …), tranne in `locals`; `backend`, `dynamic`, `provisioner` hanno 1 livello di etichetta;
- le stringhe sono template: con interpolazione `literal()` è None; `raw` di una stringa che è un'unica
  interpolazione `"${expr}"` è `expr`, altrimenti è il JSON del valore; le chiavi `"//"` (commenti) sono ignorate.

`.tfvars`/`.tfvars.json`: `parse_tfvars` restituisce gli attributi; `parse` li restituisce come unico blocco di tipo
`tfvars` senza etichette.
"""
import bisect
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

Literal = Union[str, bool, int, float, list, dict]

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n")
_NUMBER = re.compile(r"-?[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?")
_INTERP = re.compile(r"(?<!\$)\$\{|(?<!%)%\{")
_SINGLE_INTERP = re.compile(r"\$\{([^{}]*)\}")
_NO_JSON = object()

_JSON_LABELS = {
    "resource": 2, "data": 2,
    "module": 1, "provider": 1, "variable": 1, "output": 1, "check": 1,
    "terraform": 0, "locals": 0, "moved": 0, "import": 0, "removed": 0,
}
_JSON_NESTED_LABELS = {"backend": 1, "dynamic": 1, "provisioner": 1}


class _NotLiteral(Exception):
    pass


@dataclass
class Attr:
    name: str
    line: int
    raw: str
    json_value: Any = field(default=_NO_JSON, repr=False, compare=False)

    def literal(self) -> Optional[Literal]:
        """Valore Python dell'espressione se è un letterale, altrimenti None (anche per `null`)."""
        try:
            if self.json_value is not _NO_JSON:
                return _json_literal(self.json_value)
            return _LiteralParser(self.raw).parse()
        except (_NotLiteral, RecursionError, ValueError, IndexError):
            return None

    def entries(self) -> Optional[Dict[str, "Attr"]]:
        """Voci di primo livello di un oggetto `{ k = expr }` come Attr; None se l'espressione non è un oggetto."""
        try:
            if self.json_value is not _NO_JSON:
                if not isinstance(self.json_value, dict):
                    return None
                return {k: _json_attr(k, self.line, v) for k, v in self.json_value.items()}
            return _object_entries(self.raw, self.line)
        except (RecursionError, ValueError, IndexError):
            return None


@dataclass
class Block:
    type: str
    labels: List[str]
    line: int
    end_line: int
    attrs: Dict[str, Attr] = field(default_factory=dict)
    blocks: List["Block"] = field(default_factory=list)

    def get(self, name: str) -> Optional[Attr]:
        return self.attrs.get(name)

    def children(self, type: str) -> List["Block"]:
        return [b for b in self.blocks if b.type == type]

    def address(self) -> str:
        """Indirizzo Terraform: `tipo.nome` per le risorse, `var.x` per le variabili, `<tipo>.<etichette>` altrimenti."""
        if self.type == "resource":
            return ".".join(self.labels)
        return ".".join(["var" if self.type == "variable" else self.type] + self.labels)




# --- scansione lessicale ---------------------------------------------------------------------------------------------
# `issues` (facoltativo) raccoglie (offset, messaggio) dei problemi; `blanks` (facoltativo) gli intervalli dei commenti
# trovati dentro le interpolazioni, che strip_comments sostituisce con spazi.

Issues = Optional[List[Tuple[int, str]]]
Blanks = Optional[List[Tuple[int, int]]]


def _report(issues: Issues, offset: int, msg: str) -> None:
    if issues is not None:
        issues.append((offset, msg))


def _skip_string(text: str, i: int, issues: Issues = None, blanks: Blanks = None) -> int:
    """Da `"` in posizione i restituisce l'indice dopo la chiusura (o il fine riga se non è chiusa)."""
    n = len(text)
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        elif c == "\n":
            _report(issues, i, "stringa non chiusa")
            return j
        elif text.startswith("$${", j) or text.startswith("%%{", j):
            j += 3
        elif text.startswith("${", j) or text.startswith("%{", j):
            j = _skip_interp(text, j + 2, issues, blanks, j)
        else:
            j += 1
    _report(issues, i, "stringa non chiusa")
    return n


def _skip_interp(text: str, j: int, issues: Issues = None, blanks: Blanks = None, start: int = 0) -> int:
    """Da dopo `${` restituisce l'indice dopo la `}` corrispondente, saltando stringhe e commenti annidati."""
    n = len(text)
    depth = 1
    while j < n:
        c = text[j]
        if c == '"':
            j = _skip_string(text, j, issues, blanks)
            continue
        if c == "#" or text.startswith("//", j):
            k = text.find("\n", j)
            k = n if k < 0 else k
            if blanks is not None:
                blanks.append((j, k))
            j = k
            continue
        if text.startswith("/*", j):
            k = text.find("*/", j + 2)
            if k < 0:
                _report(issues, j, "commento /* non chiuso")
                k = n
            else:
                k += 2
            if blanks is not None:
                blanks.append((j, k))
            j = k
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    _report(issues, start, "interpolazione non chiusa")
    return n


def _skip_heredoc(text: str, i: int, issues: Issues = None) -> Optional[int]:
    """Se in i inizia un heredoc restituisce l'indice di fine della riga terminatrice, altrimenti None."""
    m = _HEREDOC.match(text, i)
    if not m:
        return None
    marker = m.group(2)
    j = m.end()
    n = len(text)
    while j < n:
        k = text.find("\n", j)
        k = n if k < 0 else k
        if text[j:k].strip() == marker:
            return k
        j = k + 1
    _report(issues, i, f"heredoc non chiuso (manca {marker})")
    return n


def _blank(s: str) -> str:
    return "".join(c if c in "\r\n" else " " for c in s)


def _strip(text: str, issues: Issues = None) -> str:
    out: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "#" or text.startswith("//", i):
            k = text.find("\n", i)
            k = n if k < 0 else k
            out.append(_blank(text[i:k]))
            i = k
        elif text.startswith("/*", i):
            k = text.find("*/", i + 2)
            if k < 0:
                _report(issues, i, "commento /* non chiuso")
                k = n
            else:
                k += 2
            out.append(_blank(text[i:k]))
            i = k
        elif c == '"':
            blanks: List[Tuple[int, int]] = []
            k = _skip_string(text, i, issues, blanks)
            seg = text[i:k]
            for a, b in sorted(blanks, reverse=True):
                seg = seg[:a - i] + _blank(text[a:b]) + seg[b - i:]
            out.append(seg)
            i = k
        elif c == "<":
            k = _skip_heredoc(text, i, issues)
            if k is None:
                out.append(c)
                i += 1
            else:
                out.append(text[i:k])
                i = k
        else:
            out.append(c)
            i += 1
    return "".join(out)


def strip_comments(text: str) -> str:
    """Sostituisce i commenti `#`, `//`, `/* */` con spazi, anche dentro le interpolazioni `${}`; stringhe e heredoc
    restano intatti.

    La lunghezza e le righe del testo non cambiano, quindi offset e numeri di riga restano validi.
    """
    return _strip(text)


def _expr_end(text: str, i: int, stop_comma: bool = False, issues: Issues = None) -> int:
    """Fine di un'espressione che inizia in i: fine riga, `}` non bilanciata (o `,` se richiesto) a profondità 0."""
    start, n = i, len(text)
    depth = 0
    while i < n:
        c = text[i]
        if c == '"':
            i = _skip_string(text, i)
            continue
        if c == "<":
            k = _skip_heredoc(text, i)
            if k is not None:
                i = k
                continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and (c == "\n" or (stop_comma and c == ",")):
            return i
        i += 1
    if depth > 0:
        _report(issues, start, "parentesi non chiusa nell'espressione")
    return n


def _skip_braces(text: str, i: int) -> int:
    """Da dopo una `{` restituisce l'indice della `}` corrispondente (o la fine del testo)."""
    n = len(text)
    depth = 0
    while i < n:
        c = text[i]
        if c == '"':
            i = _skip_string(text, i)
            continue
        if c == "<":
            k = _skip_heredoc(text, i)
            if k is not None:
                i = k
                continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0 and c == "}":
                return i
            depth = max(depth - 1, 0)
        i += 1
    return n


# --- parser HCL ------------------------------------------------------------------------------------------------------

_MAX_DEPTH = 100  # oltre questa profondità il contenuto è saltato e segnalato (protezione da RecursionError)


class _Lines:
    def __init__(self, text: str):
        self.nl = [m.start() for m in re.finditer("\n", text)]

    def of(self, i: int) -> int:
        return bisect.bisect_left(self.nl, i) + 1


def _skip_ws(text: str, i: int, newlines: bool = True) -> int:
    n = len(text)
    while i < n and (text[i] in " \t\r" or (newlines and text[i] == "\n")):
        i += 1
    return i


def _string_value(token: str) -> str:
    """Valore di una stringa tra virgolette; se non è letterale restituisce il contenuto grezzo."""
    try:
        return _LiteralParser(token).parse_string_only()
    except (_NotLiteral, IndexError, ValueError):
        return token[1:-1] if token.endswith('"') else token[1:]


def _parse_body(text: str, i: int, lines: _Lines, top: bool, issues: List[Tuple[int, str]],
                depth: int = 0) -> Tuple[Dict[str, Attr], List[Block], int, bool]:
    """Analizza un corpo fino alla `}` di chiusura; restituisce (attributi, blocchi, indice di `}`, chiuso)."""
    attrs: Dict[str, Attr] = {}
    blocks: List[Block] = []
    n = len(text)
    while True:
        i = _skip_ws(text, i)
        if i >= n:
            return attrs, blocks, n, top
        if text[i] == "}":
            if top:
                issues.append((i, "graffa di chiusura in eccesso"))
                i += 1
                continue
            return attrs, blocks, i, True
        m = _IDENT.match(text, i)
        if not m:
            issues.append((i, "elemento non riconosciuto"))
            end = _expr_end(text, i)
            i = end if end > i else i + 1
            continue
        name, start = m.group(0), i
        j = _skip_ws(text, m.end(), newlines=False)
        if j < n and text[j] == "=" and not text.startswith("==", j):
            vs = _skip_ws(text, j + 1, newlines=False)
            ve = _expr_end(text, vs, issues=issues)
            raw = text[vs:ve].strip()
            if not raw:
                issues.append((start, f"espressione mancante per '{name}'"))
            attrs[name] = Attr(name, lines.of(start), raw)
            i = ve
            continue
        labels: List[str] = []
        while j < n:
            if text[j] == '"':
                k = _skip_string(text, j)
                labels.append(_string_value(text[j:k]))
                j = _skip_ws(text, k, newlines=False)
                continue
            lm = _IDENT.match(text, j)
            if lm:
                labels.append(lm.group(0))
                j = _skip_ws(text, lm.end(), newlines=False)
                continue
            break
        if j < n and text[j] == "{":
            if depth >= _MAX_DEPTH:
                issues.append((start, f"annidamento oltre la profondità massima ({_MAX_DEPTH}): contenuto non analizzato"))
                battrs, bblocks, close = {}, [], _skip_braces(text, j + 1)
                closed = close < n
            else:
                battrs, bblocks, close, closed = _parse_body(text, j + 1, lines, False, issues, depth + 1)
            if not closed:
                issues.append((start, f"blocco '{name}' non chiuso"))
                return attrs, blocks, close, False
            blocks.append(Block(name, labels, lines.of(start), lines.of(close), battrs, bblocks))
            i = close + 1
            continue
        issues.append((start, "elemento non riconosciuto"))
        end = _expr_end(text, m.end())
        i = end if end > i else i + 1


def _parse_hcl(text: str, issues: List[Tuple[int, str]]) -> Tuple[Dict[str, Attr], List[Block]]:
    code = _strip(text, issues)
    attrs, blocks, _, _ = _parse_body(code, 0, _Lines(code), True, issues)
    return attrs, blocks


# --- valutazione dei letterali ---------------------------------------------------------------------------------------

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


class _LiteralParser:
    def __init__(self, s: str):
        self.s = s
        self.i = 0

    def parse(self) -> Literal:
        v = self.value()
        self.ws()
        if self.i != len(self.s):
            raise _NotLiteral
        if v is None:
            raise _NotLiteral
        return v

    def parse_string_only(self) -> str:
        v = self.string()
        if self.i != len(self.s):
            raise _NotLiteral
        return v

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t\r\n":
            self.i += 1

    def value(self) -> Any:
        self.ws()
        s, i = self.s, self.i
        if i >= len(s):
            raise _NotLiteral
        c = s[i]
        if c == '"':
            return self.string()
        if c == "<":
            return self.heredoc()
        if c == "[":
            return self.list_()
        if c == "{":
            return self.object_()
        m = _NUMBER.match(s, i)
        if m and not _IDENT.match(s, m.end()):
            self.i = m.end()
            text = m.group(0)
            return float(text) if m.group(1) or m.group(2) else int(text)
        m = _IDENT.match(s, i)
        if m and m.group(0) in ("true", "false", "null"):
            self.i = m.end()
            return {"true": True, "false": False, "null": None}[m.group(0)]
        raise _NotLiteral

    def string(self) -> str:
        s = self.s
        j = self.i + 1
        out: List[str] = []
        while j < len(s):
            c = s[j]
            if c == '"':
                self.i = j + 1
                return "".join(out)
            if c == "\n":
                raise _NotLiteral
            if c == "\\":
                e = s[j + 1]
                if e in _ESCAPES:
                    out.append(_ESCAPES[e])
                    j += 2
                elif e == "u":
                    out.append(chr(int(s[j + 2:j + 6], 16)))
                    j += 6
                elif e == "U":
                    out.append(chr(int(s[j + 2:j + 10], 16)))
                    j += 10
                else:
                    raise _NotLiteral
                continue
            if s.startswith("$${", j) or s.startswith("%%{", j):
                out.append(s[j + 1:j + 3])
                j += 3
                continue
            if s.startswith("${", j) or s.startswith("%{", j):
                raise _NotLiteral
            out.append(c)
            j += 1
        raise _NotLiteral

    def heredoc(self) -> str:
        m = _HEREDOC.match(self.s, self.i)
        if not m:
            raise _NotLiteral
        indent, marker = m.group(1) == "-", m.group(2)
        body: List[str] = []
        j = m.end()
        while True:
            if j >= len(self.s):
                raise _NotLiteral
            k = self.s.find("\n", j)
            k = len(self.s) if k < 0 else k
            line = self.s[j:k].rstrip("\r")
            if line.strip() == marker:
                self.i = k
                break
            body.append(line)
            j = k + 1
        if indent:
            widths = [len(x) - len(x.lstrip(" \t")) for x in body if x.strip()]
            cut = min(widths) if widths else 0
            body = [x[cut:] for x in body]
        content = "".join(x + "\n" for x in body)
        if _INTERP.search(content):
            raise _NotLiteral
        return content.replace("$${", "${").replace("%%{", "%{")

    def list_(self) -> list:
        self.i += 1
        out: list = []
        while True:
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value())
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == ",":
                self.i += 1
            elif not (self.i < len(self.s) and self.s[self.i] == "]"):
                raise _NotLiteral

    def object_(self) -> dict:
        self.i += 1
        out: dict = {}
        while True:
            self.ws()
            s = self.s
            if self.i >= len(s):
                raise _NotLiteral
            if s[self.i] == "}":
                self.i += 1
                return out
            if s[self.i] == '"':
                key = self.string()
            else:
                m = _IDENT.match(s, self.i)
                if not m:
                    raise _NotLiteral
                key = m.group(0)
                self.i = m.end()
            self.ws()
            if self.i >= len(s) or s[self.i] not in "=:":
                raise _NotLiteral
            self.i += 1
            out[key] = self.value()
            while self.i < len(s) and s[self.i] in " \t\r":
                self.i += 1
            if self.i < len(s) and s[self.i] in ",\n":
                self.i += 1
            elif not (self.i < len(s) and s[self.i] == "}"):
                raise _NotLiteral


def _object_entries(raw: str, line: int) -> Optional[Dict[str, Attr]]:
    s = raw
    i = _skip_ws(s, 0)
    if i >= len(s) or s[i] != "{":
        return None
    i += 1
    out: Dict[str, Attr] = {}
    while True:
        while i < len(s) and s[i] in " \t\r\n,":
            i += 1
        if i >= len(s):
            return None
        if s[i] == "}":
            return out
        kstart = i
        if s[i] == '"':
            k = _skip_string(s, i)
            key = _string_value(s[i:k])
            i = k
        else:
            m = _IDENT.match(s, i)
            if not m:
                return None
            key, i = m.group(0), m.end()
        i = _skip_ws(s, i, newlines=False)
        if i >= len(s) or s[i] not in "=:":
            return None
        vs = _skip_ws(s, i + 1, newlines=False)
        ve = _expr_end(s, vs, stop_comma=True)
        out[key] = Attr(key, line + s.count("\n", 0, kstart), s[vs:ve].strip())
        i = ve


# --- JSON ------------------------------------------------------------------------------------------------------------

class _J:
    """Valore JSON con le righe: items è [(chiave, riga, _J)] per gli oggetti, [_J] per le liste."""
    __slots__ = ("value", "line", "end_line", "items")

    def __init__(self, value: Any, line: int, end_line: int, items: Any = None):
        self.value, self.line, self.end_line, self.items = value, line, end_line, items


class _Opaque:
    """Valore JSON oltre la profondità massima: non analizzato, conservato come testo."""
    __slots__ = ("text",)

    def __init__(self, text: str):
        self.text = text


class _JsonError(Exception):
    def __init__(self, pos: int, msg: str):
        super().__init__(msg)
        self.pos, self.msg = pos, msg


class _JsonReader:
    """Lettore JSON con righe e profondità limitata: oltre `_MAX_DEPTH` il valore diventa `_Opaque` e se ne annota
    l'offset in `capped`, così il resto del documento viene comunque letto."""
    _ws = re.compile(r"[ \t\r\n]*")

    def __init__(self, text: str):
        self.text = text
        self.lines = _Lines(text)
        self.decoder = json.JSONDecoder()
        self.capped: List[int] = []

    def skip(self, i: int) -> int:
        return self._ws.match(self.text, i).end()

    def expect(self, i: int, chars: str, msg: str) -> str:
        c = self.text[i:i + 1]
        if not c or c not in chars:
            raise _JsonError(i, msg)
        return c

    def key(self, i: int) -> Tuple[str, int]:
        self.expect(i, '"', "chiave tra virgolette attesa")
        try:
            return json.decoder.scanstring(self.text, i + 1)
        except ValueError as e:
            raise _JsonError(getattr(e, "pos", i), "stringa non valida")

    def opaque_end(self, i: int) -> int:
        t, n = self.text, len(self.text)
        depth = 0
        while i < n:
            c = t[i]
            if c == '"':
                _, i = self.key(i)
                continue
            if c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        raise _JsonError(n, "documento troncato")

    def read(self, i: int, depth: int = 0) -> Tuple[_J, int]:
        t = self.text
        i = self.skip(i)
        if i >= len(t):
            raise _JsonError(i, "valore mancante")
        line = self.lines.of(i)
        c = t[i]
        if c in "{[" and depth >= _MAX_DEPTH:
            end = self.opaque_end(i)
            self.capped.append(i)
            return _J(_Opaque(t[i:end]), line, self.lines.of(end - 1)), end
        if c == "{":
            items, value = [], {}
            i = self.skip(i + 1)
            if t[i:i + 1] != "}":
                while True:
                    kline = self.lines.of(i)
                    key, i = self.key(i)
                    i = self.skip(i)
                    self.expect(i, ":", "':' attesi")
                    node, i = self.read(i + 1, depth + 1)
                    items.append((key, kline, node))
                    value[key] = node.value
                    i = self.skip(i)
                    if self.expect(i, ",}", "',' o '}' attesi") == "}":
                        break
                    i = self.skip(i + 1)
            return _J(value, line, self.lines.of(i), items), i + 1
        if c == "[":
            nodes = []
            i = self.skip(i + 1)
            if t[i:i + 1] != "]":
                while True:
                    node, i = self.read(i, depth + 1)
                    nodes.append(node)
                    i = self.skip(i)
                    if self.expect(i, ",]", "',' o ']' attesi") == "]":
                        break
                    i = self.skip(i + 1)
            return _J([x.value for x in nodes], line, self.lines.of(i), nodes), i + 1
        try:
            value, end = self.decoder.raw_decode(t, i)
        except ValueError as e:
            raise _JsonError(getattr(e, "pos", i), "valore non valido")
        return _J(value, line, self.lines.of(end)), end


def _json_literal(v: Any) -> Any:
    if isinstance(v, str):
        if _INTERP.search(v):
            raise _NotLiteral
        return v.replace("$${", "${").replace("%%{", "%{")
    if isinstance(v, list):
        return [_json_literal(x) for x in v]
    if isinstance(v, dict):
        return {k: _json_literal(x) for k, x in v.items() if k != "//"}
    if v is None or isinstance(v, _Opaque):
        raise _NotLiteral
    return v


def _json_attr(name: str, line: int, value: Any) -> Attr:
    if isinstance(value, str):
        m = _SINGLE_INTERP.fullmatch(value)
        raw = m.group(1).strip() if m else json.dumps(value, ensure_ascii=False)
    elif isinstance(value, _Opaque):
        raw = value.text
    else:
        raw = json.dumps(value, ensure_ascii=False, default=lambda o: o.text if isinstance(o, _Opaque) else str(o))
    return Attr(name, line, raw, value)


def _json_body(node: _J, btype: str) -> Tuple[Dict[str, Attr], List[Block]]:
    attrs: Dict[str, Attr] = {}
    blocks: List[Block] = []
    for key, kline, child in node.items or []:
        if key == "//":
            continue
        attrs[key] = _json_attr(key, kline, child.value)
        if btype == "locals":
            continue
        if key in _JSON_NESTED_LABELS:
            blocks.extend(_json_blocks(key, child, _JSON_NESTED_LABELS[key], [], kline))
        elif isinstance(child.value, dict) or (
            isinstance(child.value, list) and child.value and all(isinstance(x, dict) for x in child.value)
        ):
            blocks.extend(_json_blocks(key, child, 0, [], kline))
    return attrs, blocks


def _json_blocks(btype: str, node: _J, nlabels: int, labels: List[str], line: int) -> List[Block]:
    out: List[Block] = []
    if isinstance(node.value, list):
        # a ogni livello (etichette o corpo) una lista di oggetti equivale a più oggetti dello stesso livello
        for item in node.items:
            out.extend(_json_blocks(btype, item, nlabels, labels, item.line))
        return out
    if not isinstance(node.value, dict):
        return out
    if nlabels > 0:
        for key, kline, child in node.items:
            if key != "//":
                out.extend(_json_blocks(btype, child, nlabels - 1, labels + [key], kline))
        return out
    attrs, blocks = _json_body(node, btype)
    return [Block(btype, list(labels), line, node.end_line, attrs, blocks)]


def _read_json(text: str, issues: List[Tuple[int, str]]) -> Optional[_J]:
    reader = _JsonReader(text)
    try:
        root, end = reader.read(0)
        end = reader.skip(end)
        if end != len(text):
            raise _JsonError(end, "contenuto dopo la fine del documento")
    except _JsonError as e:
        issues.append((e.pos, f"JSON non valido: {e.msg}"))
        return None
    for pos in reader.capped:
        issues.append((pos, f"annidamento oltre la profondità massima ({_MAX_DEPTH}): contenuto non analizzato"))
    if not isinstance(root.value, dict):
        issues.append((0, "il documento JSON non è un oggetto"))
        return None
    return root


# --- API -------------------------------------------------------------------------------------------------------------

def _analyze(text: str, filename: str) -> Tuple[Dict[str, Attr], List[Block], List[Tuple[int, str]]]:
    """Analizza il file secondo l'estensione; restituisce (attributi di primo livello, blocchi, problemi per riga)."""
    issues: List[Tuple[int, str]] = []
    attrs: Dict[str, Attr] = {}
    blocks: List[Block] = []
    try:
        if filename.endswith((".tf.json", ".tfvars.json")):
            root = _read_json(text, issues)
            if root is not None:
                if filename.endswith(".tfvars.json"):
                    attrs = {k: _json_attr(k, line, c.value) for k, line, c in root.items if k != "//"}
                else:
                    for key, kline, child in root.items:
                        if key in _JSON_LABELS:
                            blocks.extend(_json_blocks(key, child, _JSON_LABELS[key], [], kline))
        else:
            attrs, blocks = _parse_hcl(text, issues)
    except RecursionError:
        issues.append((0, "errore interno del parser: annidamento troppo profondo"))
        attrs, blocks = {}, []
    except Exception as e:  # il parser non deve mai sollevare: ogni errore diventa un problema
        issues.append((0, f"errore interno del parser: {type(e).__name__}"))
        attrs, blocks = {}, []
    lines = _Lines(text)
    problems = sorted({(lines.of(off), msg) for off, msg in issues})
    return attrs, blocks, problems


def parse_tfvars(text: str, filename: str) -> Dict[str, Attr]:
    """Attributi di un file `.tfvars` o `.tfvars.json`; {} se il file non è leggibile."""
    return _analyze(text, filename)[0]


def parse(text: str, filename: str = "main.tf") -> List[Block]:
    """Blocchi di primo livello di un file Terraform; il formato è dedotto dall'estensione. Non solleva mai."""
    attrs, blocks, _ = _analyze(text, filename)
    if filename.endswith((".tfvars", ".tfvars.json")):
        return [Block("tfvars", [], 1, text.count("\n") + 1, attrs, [])]
    return blocks


def parse_problems(text: str, filename: str = "main.tf") -> List[Tuple[int, str]]:
    """(riga, messaggio) per ogni punto in cui `parse` non ha potuto vedere tutto il file: blocco o parentesi non
    chiusi, stringa/heredoc/commento non chiusi, elemento non riconosciuto, JSON non valido, profondità massima
    raggiunta, errore interno. Lista vuota = file compreso per intero."""
    return _analyze(text, filename)[2]
