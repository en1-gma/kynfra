"""Parser YAML minimo per gli OpenAPI dei progetti kybes. Solo libreria standard.

Sottoinsieme supportato: un solo documento (con `---` iniziale facoltativo e `...` finale), mappe e liste a blocchi,
collezioni flow `{}` e `[]` (anche su più righe), scalari plain/quotati (`'...'` e `"..."` con escape), scalari plain
su più righe, blocchi `|` e `>` (con chomping `-`/`+` e indentazione esplicita), commenti `#`. Accetta anche JSON
(chiavi duplicate rifiutate anche lì).
Le chiavi delle mappe sono sempre stringhe (`200:` diventa "200").

Fuori dal sottoinsieme (anchor `&`, alias `*`, tag `!`, direttive `%`, chiavi complesse `?`, più documenti, tab
nell'indentazione, chiavi duplicate): `MiniYamlError` con la riga. Chi lo usa per un controllo deve trattarlo come un
errore bloccante (fail closed), non come un file vuoto.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple, Union

Path_ = Tuple[Union[str, int], ...]

_FORBIDDEN = {"&": "anchor (&) non supportate", "*": "alias (*) non supportati", "!": "tag (!) non supportati",
              "%": "direttive (%) non supportate", "?": "chiavi complesse (?) non supportate",
              "@": "carattere riservato @", "`": "carattere riservato `"}
_FORBIDDEN_START = "&*!@`"
_BLOCK_HEADER = re.compile(r"([|>])([+-]?)([1-9]?)([+-]?)$")
_INT = re.compile(r"[-+]?[0-9]+$")
_FLOAT = re.compile(r"[-+]?([0-9]+\.[0-9]*|\.[0-9]+|[0-9]+)([eE][-+]?[0-9]+)?$")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "/": "/", "b": "\b", "f": "\f",
            " ": " ", "e": "\x1b", "a": "\a", "v": "\v"}


class MiniYamlError(ValueError):
    pass


def load(text: str) -> Any:
    """Valore Python del documento YAML (o JSON)."""
    return load_with_lines(text)[0]


def load_with_lines(text: str) -> Tuple[Any, Dict[Path_, int]]:
    """(valore, righe): `righe` associa il percorso di ogni chiave di mappa e voce di lista (tupla di chiavi e indici,
    es. ("paths", "/v1/x", "get")) alla riga (da 1) in cui compare. Per i documenti JSON `righe` è vuoto."""
    text = text.lstrip("\ufeff")
    if text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text, object_pairs_hook=_json_object), {}
        except MiniYamlError:
            raise
        except ValueError:
            pass  # YAML flow, non JSON
    p = _Parser(text)
    return p.document(), p.lines


def _json_object(pairs: List[Tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise MiniYamlError(f"chiave duplicata {k!r} nel JSON")
        out[k] = v
    return out


def _scalar(s: str, line: int) -> Any:
    if s in ("", "~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if _INT.match(s):
        return int(s)
    if _FLOAT.match(s):
        return float(s)
    if s[0] in _FORBIDDEN_START:
        raise MiniYamlError(f"riga {line}: {_FORBIDDEN[s[0]]}")
    return s


def _read_quoted(s: str, i: int, line: int) -> Tuple[Optional[str], int]:
    """(stringa, indice dopo la virgoletta di chiusura) della stringa quotata che inizia in s[i]; (None, len) se non
    si chiude in `s`."""
    q = s[i]
    out: List[str] = []
    j = i + 1
    while j < len(s):
        c = s[j]
        if q == "'" and c == "'":
            if s.startswith("''", j):
                out.append("'")
                j += 2
                continue
            return "".join(out), j + 1
        if q == '"' and c == '"':
            return "".join(out), j + 1
        if q == '"' and c == "\\":
            if j + 1 >= len(s):
                return None, len(s)
            e = s[j + 1]
            if e in _ESCAPES:
                out.append(_ESCAPES[e])
                j += 2
                continue
            n = {"x": 2, "u": 4, "U": 8}.get(e)
            if n and re.fullmatch(r"[0-9a-fA-F]{%d}" % n, s[j + 2:j + 2 + n]):
                out.append(chr(int(s[j + 2:j + 2 + n], 16)))
                j += 2 + n
                continue
            raise MiniYamlError(f"riga {line}: escape non valido \\{e}")
        out.append(c)
        j += 1
    return None, len(s)


def _strip_comment(s: str) -> str:
    """Toglie il commento `#` (a inizio riga o dopo uno spazio) fuori dalle stringhe quotate."""
    q = ""
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            if q == '"' and c == "\\":
                i += 2
                continue
            if c == q:
                if q == "'" and s.startswith("''", i):
                    i += 2
                    continue
                q = ""
        elif c in "'\"" and (i == 0 or s[i - 1] in " \t[{,"):
            q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
        i += 1
    return s.rstrip()


def _flow_depth(s: str) -> int:
    """Profondità di `{`/`[` aperte (fuori dalle stringhe) alla fine di `s`."""
    depth, q, i = 0, "", 0
    while i < len(s):
        c = s[i]
        if q:
            if q == '"' and c == "\\":
                i += 1
            elif c == q:
                q = ""
        elif c in "'\"" and (i == 0 or s[i - 1] in " \t[{,:"):
            q = c
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        i += 1
    return depth


class _Flow:
    """Collezioni flow `{a: 1, b: [x, y]}` su una stringa già unita."""

    def __init__(self, s: str, line: int):
        self.s, self.i, self.line = s, 0, line

    def err(self, msg: str) -> MiniYamlError:
        return MiniYamlError(f"riga {self.line}: {msg}")

    def ws(self) -> None:
        while self.i < len(self.s) and self.s[self.i] in " \t\n":
            self.i += 1

    def whole(self) -> Any:
        v = self.value()
        self.ws()
        if self.i != len(self.s):
            raise self.err(f"contenuto inatteso dopo la collezione flow: {self.s[self.i:]!r}")
        return v

    def value(self) -> Any:
        self.ws()
        if self.i >= len(self.s):
            raise self.err("collezione flow non chiusa")
        c = self.s[self.i]
        if c == "{":
            return self.mapping()
        if c == "[":
            return self.sequence()
        if c in "'\"":
            v, j = _read_quoted(self.s, self.i, self.line)
            if v is None:
                raise self.err("stringa non chiusa")
            self.i = j
            return v
        return _scalar(self.plain(key=False), self.line)

    def plain(self, key: bool) -> str:
        start = self.i
        while self.i < len(self.s):
            c = self.s[self.i]
            if c in ",[]{}":
                break
            if c == ":" and (self.i + 1 == len(self.s) or self.s[self.i + 1] in " ,]}" or key):
                break
            self.i += 1
        return self.s[start:self.i].strip()

    def mapping(self) -> dict:
        self.i += 1
        out: dict = {}
        while True:
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "}":
                self.i += 1
                return out
            if self.i < len(self.s) and self.s[self.i] in "'\"":
                key, self.i = _read_quoted(self.s, self.i, self.line)
                if key is None:
                    raise self.err("stringa non chiusa")
            else:
                raw = self.plain(key=True)
                if raw[:1] in _FORBIDDEN_START:
                    raise self.err(_FORBIDDEN[raw[0]])
                key = raw
            self.ws()
            value = None
            if self.i < len(self.s) and self.s[self.i] == ":":
                self.i += 1
                self.ws()
                if self.i < len(self.s) and self.s[self.i] not in ",}":
                    value = self.value()
            if key in out:
                raise self.err(f"chiave duplicata {key!r}")
            out[str(key)] = value
            self.ws()
            if self.i >= len(self.s):
                raise self.err("mappa flow non chiusa")
            if self.s[self.i] == ",":
                self.i += 1
            elif self.s[self.i] != "}":
                raise self.err("atteso ',' o '}' nella mappa flow")

    def sequence(self) -> list:
        self.i += 1
        out: list = []
        while True:
            self.ws()
            if self.i < len(self.s) and self.s[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value())
            self.ws()
            if self.i >= len(self.s):
                raise self.err("lista flow non chiusa")
            if self.s[self.i] == ",":
                self.i += 1
            elif self.s[self.i] != "]":
                raise self.err("atteso ',' o ']' nella lista flow")


def _is_seq(content: str) -> bool:
    return content == "-" or content.startswith("- ")


class _Parser:
    def __init__(self, text: str):
        self.raw = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        self.pos = 0
        self.override: Dict[int, Tuple[int, str]] = {}
        self.lines: Dict[Path_, int] = {}

    def err(self, idx: int, msg: str) -> MiniYamlError:
        return MiniYamlError(f"riga {idx + 1}: {msg}")

    # --- righe logiche

    def line_at(self, idx: int) -> Optional[Tuple[int, str]]:
        """(indentazione, contenuto senza commento) della riga; None se vuota o solo commento."""
        if idx in self.override:
            return self.override[idx]
        raw = self.raw[idx]
        body = raw.lstrip(" \t")
        lead = raw[:len(raw) - len(body)]
        content = _strip_comment(body)
        if not content:
            return None
        if "\t" in lead:
            raise self.err(idx, "tab nell'indentazione non ammessi")
        return len(lead), content

    def _marker(self, ind: int, content: str) -> bool:
        return ind == 0 and (content in ("---", "...") or content.startswith("--- "))

    def peek(self) -> Optional[Tuple[int, int, str]]:
        """(indice, indentazione, contenuto) della prossima riga utile da `pos`; None a fine documento."""
        idx = self.pos
        while idx < len(self.raw):
            got = self.line_at(idx)
            if got is not None:
                if self._marker(*got):
                    return None
                return idx, got[0], got[1]
            idx += 1
        return None

    # --- documento

    def document(self) -> Any:
        idx = self._skip_blank(0)
        if idx < len(self.raw):
            ind, content = self.line_at(idx)
            if content.startswith("%"):
                raise self.err(idx, _FORBIDDEN["%"])
            if ind == 0 and content == "---":
                idx += 1
            elif ind == 0 and content.startswith("--- "):
                raise self.err(idx, "contenuto sulla riga di '---' non supportato")
        self.pos = idx
        value = self.node(0, ())
        idx = self._skip_blank(self.pos)
        if idx < len(self.raw):
            ind, content = self.line_at(idx)
            if ind == 0 and content == "...":
                idx = self._skip_blank(idx + 1)
                if idx >= len(self.raw):
                    return value
            if ind == 0 and content.startswith("---"):
                raise self.err(idx, "più documenti YAML nello stesso file non supportati")
            raise self.err(idx, f"contenuto inatteso: {content!r}")
        return value

    def _skip_blank(self, idx: int) -> int:
        while idx < len(self.raw) and self.line_at(idx) is None:
            idx += 1
        return idx

    # --- nodi a blocchi

    def node(self, min_indent: int, path: Path_) -> Any:
        nxt = self.peek()
        if nxt is None or nxt[1] < min_indent:
            return None
        idx, ind, content = nxt
        if _is_seq(content):
            return self.sequence(ind, path)
        if self.split_key(content, idx) is not None:
            return self.mapping(ind, path)
        self.pos = idx + 1
        return self.inline(content, idx, ind - 1)

    def split_key(self, content: str, idx: int) -> Optional[Tuple[str, str]]:
        """(chiave, resto) se la riga è `chiave: ...`, altrimenti None."""
        if content[0] in "{[":
            return None
        if content == "?" or content.startswith("? "):
            raise self.err(idx, _FORBIDDEN["?"])
        if content[0] in "'\"":
            key, j = _read_quoted(content, 0, idx + 1)
            if key is None:
                return None
            rest = content[j:].lstrip()
            if rest == ":" or rest.startswith(": "):
                return key, rest[1:].strip()
            return None
        m = re.search(r":( |$)", content)
        if not m:
            return None
        key = content[:m.start()].strip()
        if key[:1] in _FORBIDDEN_START:
            raise self.err(idx, _FORBIDDEN[key[0]])
        return key, content[m.end():].strip()

    def mapping(self, ind: int, path: Path_) -> dict:
        out: dict = {}
        while True:
            nxt = self.peek()
            if nxt is None or nxt[1] < ind:
                return out
            idx, i2, content = nxt
            if i2 > ind:
                raise self.err(idx, "indentazione inattesa")
            if _is_seq(content):
                raise self.err(idx, "voce di lista dentro una mappa")
            kv = self.split_key(content, idx)
            if kv is None:
                raise self.err(idx, f"attesa 'chiave: valore', trovato {content!r}")
            key, rest = kv
            if key in out:
                raise self.err(idx, f"chiave duplicata {key!r}")
            self.lines[path + (key,)] = idx + 1
            self.pos = idx + 1
            out[key] = self.value(rest, idx, ind, path + (key,))

    def sequence(self, ind: int, path: Path_) -> list:
        out: list = []
        while True:
            nxt = self.peek()
            if nxt is None or nxt[1] < ind:
                return out
            idx, i2, content = nxt
            if i2 > ind:
                raise self.err(idx, "indentazione inattesa")
            if not _is_seq(content):
                return out  # chiave della mappa che contiene la lista (`k:\n- a\nk2: …`)
            n = len(out)
            self.lines[path + (n,)] = idx + 1
            rest = content[1:].lstrip()
            if rest and (_is_seq(rest) or self.split_key(rest, idx) is not None):
                self.override[idx] = (ind + len(content) - len(rest), rest)
                out.append(self.node(ind + 1, path + (n,)))
                continue
            self.pos = idx + 1
            out.append(self.value(rest, idx, ind, path + (n,)))

    def value(self, rest: str, idx: int, ind: int, path: Path_) -> Any:
        """Valore dopo `chiave:` o `-` (a indentazione `ind`)."""
        if rest == "":
            nxt = self.peek()
            if nxt and (nxt[1] > ind or (nxt[1] == ind and _is_seq(nxt[2]) and path and isinstance(path[-1], str))):
                return self.node(ind if nxt[1] == ind else ind + 1, path)
            return None
        if _BLOCK_HEADER.match(rest):
            return self.block_scalar(rest, idx, ind)
        return self.inline(rest, idx, ind)

    def inline(self, rest: str, idx: int, ind: int) -> Any:
        """Scalare o collezione flow che inizia sulla riga `idx`; le righe di continuazione sono quelle più indentate
        di `ind`."""
        if rest[0] in "{[":
            text = rest
            while _flow_depth(text) > 0:
                nxt = self.peek()
                if nxt is None:
                    raise self.err(idx, "collezione flow non chiusa")
                text += "\n" + nxt[2]
                self.pos = nxt[0] + 1
            return _Flow(text, idx + 1).whole()
        if rest[0] in "'\"":
            text = rest
            while True:
                v, j = _read_quoted(text, 0, idx + 1)
                if v is not None:
                    if text[j:].strip():
                        raise self.err(idx, f"contenuto inatteso dopo la stringa: {text[j:].strip()!r}")
                    return v
                if self.pos >= len(self.raw):
                    raise self.err(idx, "stringa non chiusa")
                nxt_raw = self.raw[self.pos].strip()
                self.pos += 1
                text += (" " + nxt_raw) if nxt_raw else "\n"
        parts = [rest]
        while True:
            nxt = self.peek()
            if nxt is None or nxt[1] <= ind:
                break
            parts.append(nxt[2])
            self.pos = nxt[0] + 1
        if len(parts) == 1:
            return _scalar(rest, idx + 1)
        return " ".join(parts)

    def block_scalar(self, header: str, idx: int, ind: int) -> str:
        m = _BLOCK_HEADER.match(header)
        style, chomp, explicit = m.group(1), m.group(2) or m.group(4), m.group(3)
        j = idx + 1
        block_indent = ind + int(explicit) if explicit else None
        body: List[str] = []
        while j < len(self.raw):
            raw = self.raw[j]
            if not raw.strip():
                body.append("")
                j += 1
                continue
            cur = len(raw) - len(raw.lstrip(" "))
            if block_indent is None:
                if cur <= ind:
                    break
                block_indent = cur
            if cur < block_indent:
                break
            body.append(raw[block_indent:])
            j += 1
        self.pos = j
        trailing = 0
        while body and body[-1] == "":
            body.pop()
            trailing += 1
        if style == "|":
            text = "\n".join(body)
        else:
            text, prev = "", None
            for line in body:  # righe consecutive unite da uno spazio; vuote e più indentate restano a capo
                if prev is None:
                    text = line
                elif line == "":
                    text += "\n"
                elif prev == "":
                    text += line
                elif line.startswith(" ") or prev.startswith(" "):
                    text += "\n" + line
                else:
                    text += " " + line
                prev = line
        if not body:
            return "\n" * trailing if chomp == "+" else ""
        if chomp == "-":
            return text
        if chomp == "+":
            return text + "\n" * (trailing + 1)
        return text + "\n"
