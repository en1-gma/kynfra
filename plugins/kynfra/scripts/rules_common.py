"""Regole trasversali di kynfra sul contenuto dei file Terraform (indipendenti dal provider) e dei template nativi.

Ogni regola ha la firma `(irel, blocks, text, cfg) -> List[Finding]`: `irel` è il percorso relativo a infra_root,
`blocks` i blocchi di `hcl.parse` (commenti già ignorati), `text` il testo originale. Il nome della funzione è il nome
della regola in snake_case (`remote_state` → `remote-state`). Le regole producono i finding con la severità di
default e il percorso `irel`; `rules.check_content` li riporta al percorso del progetto, applica la severità della
config e le eccezioni. Solo `scanner_suppression` (e le regole sui file in `native/`) leggono il testo con i commenti.

Le regole a livello di stack (`remote-state`, `version-pinning` su `required_version`, `account-guard`,
`required-tags`) valutano il blocco nel file in cui compare; l'assenza del blocco nell'intero stack la verifica
`check_project`.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Iterable, List, Optional, Tuple

import hcl
from rules import DEFAULT_RULES, Finding

MESSAGES = {
    "remote-state-local": "backend locale ammesso solo in bootstrap/: usa backend \"s3\" con encrypt = true e "
                          "use_lockfile = true, chiave <progetto>/<env>/<stack>.tfstate",
    "remote-state-s3": "backend s3 incompleto ({missing}): imposta encrypt = true e use_lockfile = true "
                       "(lock nativo, senza DynamoDB)",
    "version-required": "required_version senza vincolo pessimistico: usa \"~> X.Y\"",
    "version-provider": "provider '{name}' senza versione bloccata: aggiungi version = \"~> X.Y\" in "
                        "required_providers",
    "version-provider-range": "provider '{name}' con vincolo aperto ({value}): usa il vincolo pessimistico \"~> X.Y\"",
    "version-module-source": "source del modulo non letterale: Terraform richiede un percorso o un indirizzo fisso",
    "version-module-git": "modulo git senza ref fissa: aggiungi ?ref=<tag o commit> (non un branch), o meglio usa un "
                          "modulo locale in modules/",
    "version-module-registry": "modulo del registry senza versione fissa: aggiungi version = \"X.Y.Z\" (o \"~> X.Y\"), "
                               "o meglio usa un modulo locale in modules/",
    "version-module-remote": "modulo remoto senza versione verificabile: usa un modulo locale in modules/",
    "static-credentials": "credenziale statica ({name}): niente chiavi nel codice o nei tfvars, autenticati con "
                          "profilo, SSO o OIDC",
    "secrets": "segreto in chiaro: crea il contenitore (aws_secretsmanager_secret) e inserisci il valore fuori da "
               "Terraform, oppure passa var.* sensitive a un argomento write-only (*_wo)",
    "secrets-variable": "variabile riservata '{name}' senza sensitive = true: aggiungi sensitive = true e nessun "
                        "default",
    "secrets-default": "variabile riservata '{name}' con default in chiaro: togli il default, il valore lo fornisce "
                       "il DevOps fuori dal repository",
    "required-tags": "provider aws senza default_tags completi ({problems}): aggiungi default_tags {{ tags = {{ "
                     "Project, Environment, Owner, CostCenter, ManagedBy = \"kynfra\" }} }} con chiavi letterali",
    "account-guard": "provider aws senza allowed_account_ids: aggiungi allowed_account_ids = [var.account_id] così "
                     "un apply sull'account sbagliato fallisce",
    "variables-type": "variabile '{name}' senza type: dichiara il tipo (string, number, object({{…}}), …)",
    "variables-description": "variabile '{name}' senza description: aggiungi una descrizione",
    "scanner-suppression": "soppressione inline dello scanner vietata: togli il commento e, se serve davvero, chiedi "
                           "all'utente un'eccezione in .kynfra/config.json (exceptions)",
    "no-provisioners": "provisioner/esecuzione locale fuori dal controllo di Terraform: usa risorse native del "
                       "provider (user_data, SSM, cloud-init) invece di {what}",
    "region-pinning-region": "regione scritta come letterale nel modulo: passala come variabile dai tfvars "
                             "dell'ambiente",
    "region-pinning-account": "account ID scritto come letterale nel modulo: usa var.account_id o "
                              "data.aws_caller_identity",
    "native-type": "parametro '{name}' senza Type: dichiara il tipo del parametro",
    "native-default": "parametro riservato '{name}' con valore di default: togli il default, il valore arriva da un "
                      "secret manager (es. {{{{resolve:secretsmanager:…}}}})",
    "native-noecho": "parametro riservato '{name}' senza NoEcho: true: aggiungi NoEcho: true",
    "native-secure": "parametro riservato '{name}' senza @secure(): aggiungi il decoratore @secure()",
    "native-json": "template JSON non leggibile: correggi la sintassi, i guardrail non possono verificare ciò che "
                   "non leggono",
}

# ---------------------------------------------------------------- segreti: pattern (da kyfes, estesi per IaC)

PLACEHOLDER = re.compile(r"^(<[^>]*>|\$\{[^}]*\}|x{3,}|\*{3,}|changeme|change-me|replace-?me|your[-_].*|todo)$", re.I)

SECRET_RE = re.compile(
    r"""AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bsk-[A-Za-z0-9_-]{20,}|"""
    r"""\bxox[abprs]-[A-Za-z0-9-]{10,}|"""
    r"""(?P<k>client_secret|api_secret|apiSecret|clientSecret|password|passwd|private_key|connection_string|"""
    r"""api_key|api_token|secret|token)\s*[:=]\s*['"](?P<val>[^'"\s]{6,})['"]""",
    re.I)

# credenziali dentro una connection string: scheme://utente:password@host
CONN_RE = re.compile(r"""[a-z][a-z0-9+.-]*://[^\s:/@'"]+:(?P<val>[^\s@'"/]+)@""", re.I)

# suffissi (nome in minuscolo senza separatori) che rendono riservato un attributo, una variabile o una chiave
SENSITIVE_SUFFIXES = ("password", "passwd", "secret", "token", "privatekey", "connectionstring", "apikey",
                      "secretkey", "accesskey", "secretstring", "secretbinary")
# per questi nomi qualsiasi letterale è un segreto (anche corto o segnaposto: finirebbe nello stato)
STRICT_NAMES = ("secretstring", "secretbinary")

PROVIDER_CRED_ATTRS = {"access_key", "secret_key", "token", "session_token", "access_token", "client_secret",
                       "client_certificate_password", "api_token", "api_key", "password"}
CRED_NAME = re.compile(r"^(aws_)?(access_key(_id)?|secret_(access_)?key|session_token)$", re.I)

REQUIRED_TAGS = ("Project", "Environment", "Owner", "CostCenter", "ManagedBy")

SUPPRESS_RE = re.compile(r"checkov\s*:\s*skip|trivy\s*:\s*ignore|tflint-ignore|tfsec\s*:\s*ignore|"
                         r"kics\s+scan\s+ignore", re.I)

REGION_RE = re.compile(r"\b(us|eu|ap|sa|ca|me|af|il|mx|cn)(-gov|-iso[a-z]?)?-(north|south|east|west|central|"
                       r"northeast|northwest|southeast|southwest)-\d\b")
ACCOUNT_RE = re.compile(r"(?<![\d.])\d{12}(?![\d.])")

PINNED_EXACT = re.compile(r"=?\s*v?\d+(\.\d+){1,2}(-[0-9A-Za-z.]+)?")
GIT_SOURCE = re.compile(r"^(git::|hg::|git@|github\.com/|bitbucket\.org/)|\.git($|[/?])")
GIT_REF_OK = re.compile(r"v?\d+(\.\d+)*([-+.][0-9A-Za-z.]+)?|[0-9a-f]{7,40}")
REGISTRY_SOURCE = re.compile(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,}/)?[\w-]+/[\w-]+/[\w-]+(//.*)?")

TFVARS_EXT = (".tfvars", ".tfvars.json")

# blocchi annidati i cui attributi hanno nomi "riservati" ma valori non segreti (es. unità di durata dei token Cognito)
NON_SECRET_BLOCKS = {"token_validity_units"}

# valori che rimandano a un segreto invece di contenerlo (riferimenti dinamici CloudFormation, ARM, interpolazioni)
REFERENCE_VALUE = re.compile(r"^(\{\{resolve:|\$\{|\[(parameters|reference|variables)\()", re.I)
# fuori dalle virgolette anche tag YAML (!Ref, !Sub), oggetti e liste ({"Ref": …}, [...]) e scalari multi-riga
UNQUOTED_REFERENCE = re.compile(r"^[!{\[|>&*]")


def _f(rule: str, irel: str, line: int, message: str, resource: str = "") -> Finding:
    return Finding(rule, DEFAULT_RULES.get(rule, "block"), irel, line, message, resource)


def _addr(block: hcl.Block) -> str:
    return "" if block.type == "tfvars" else block.address()


def _norm(name: str) -> str:
    n = name.lower()
    if n.endswith("_wo"):
        n = n[:-3]
    return re.sub(r"[^a-z0-9]", "", n)


def _sensitive_name(name: str) -> bool:
    return _norm(name).endswith(SENSITIVE_SUFFIXES)


def _secret_hit(s: str) -> bool:
    """Segreto riconoscibile dal testo: token noti, `password = "…"` con valore vero, connection string."""
    for m in SECRET_RE.finditer(s):
        val = m.group("val")
        if val is None or not (PLACEHOLDER.match(val) or REFERENCE_VALUE.match(val)):
            return True
    for m in CONN_RE.finditer(s):
        val = m.group("val")
        if not (PLACEHOLDER.match(val) or REFERENCE_VALUE.match(val)):
            return True
    return False


def _literal_secret(attr: hcl.Attr, strict: bool = False) -> bool:
    """Valore letterale che sembra un segreto vero (non riferimenti, chiamate di funzione, segnaposto o ARN)."""
    v = attr.literal()
    if not isinstance(v, str) or not v.strip():
        return False
    if strict:
        return True
    return len(v) >= 6 and not PLACEHOLDER.match(v) and not v.startswith("arn:")


def _walk_blocks(blocks: Iterable[hcl.Block]) -> Iterable[hcl.Block]:
    for b in blocks:
        yield b
        yield from _walk_blocks(b.blocks)


def _attrs_deep(block: hcl.Block) -> Iterable[hcl.Attr]:
    """Attributi del blocco e dei blocchi annidati."""
    for b in _walk_blocks([block]):
        yield from b.attrs.values()


def _named_values(attr: hcl.Attr, depth: int = 0) -> Iterable[Tuple[str, hcl.Attr, bool]]:
    """(nome, attributo, è_oggetto) dell'attributo e, se è un oggetto, delle sue voci (ricorsivamente)."""
    entries = attr.entries() if depth < 6 else None
    yield attr.name, attr, entries is not None
    for sub in (entries or {}).values():
        yield from _named_values(sub, depth + 1)


# ---------------------------------------------------------------- regole HCL

def remote_state(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for tf in (b for b in blocks if b.type == "terraform"):
        for be in tf.children("backend"):
            kind = be.labels[0] if be.labels else ""
            res = f"terraform.backend.{kind}"
            if kind == "local" and not irel.startswith("bootstrap/"):
                out.append(_f("remote-state", irel, be.line, MESSAGES["remote-state-local"], res))
            elif kind == "s3":
                missing = [k for k in ("encrypt", "use_lockfile")
                           if not (be.get(k) and be.get(k).literal() is True)]
                if missing:
                    out.append(_f("remote-state", irel, be.line,
                                  MESSAGES["remote-state-s3"].format(missing=", ".join(missing)), res))
    return out


def _pinned(value) -> bool:
    return isinstance(value, str) and ("~>" in value or bool(PINNED_EXACT.fullmatch(value.strip())))


def version_pinning(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for tf in (b for b in blocks if b.type == "terraform"):
        rv = tf.get("required_version")
        if rv is not None and not _pinned(rv.literal()):
            out.append(_f("version-pinning", irel, rv.line, MESSAGES["version-required"], "terraform"))
        for rp in tf.children("required_providers"):
            for name, attr in rp.attrs.items():
                entries = attr.entries()
                if entries is not None:
                    ver = entries.get("version")
                    value = ver.literal() if ver is not None else None
                    line = ver.line if ver is not None else attr.line
                else:  # sintassi legacy: aws = "~> 6.0"
                    ver, value, line = attr, attr.literal(), attr.line
                if ver is None:
                    out.append(_f("version-pinning", irel, line, MESSAGES["version-provider"].format(name=name),
                                  "terraform"))
                elif not _pinned(value):
                    out.append(_f("version-pinning", irel, line,
                                  MESSAGES["version-provider-range"].format(name=name, value=ver.raw), "terraform"))
    for mod in (b for b in blocks if b.type == "module"):
        msg = _module_problem(mod)
        if msg:
            src = mod.get("source")
            out.append(_f("version-pinning", irel, src.line if src else mod.line, msg, mod.address()))
    return out


def _module_problem(mod: hcl.Block) -> Optional[str]:
    src_attr = mod.get("source")
    src = src_attr.literal() if src_attr is not None else None
    if not isinstance(src, str):
        return MESSAGES["version-module-source"]
    if src.startswith(("./", "../")):
        return None
    if GIT_SOURCE.search(src):
        m = re.search(r"[?&]ref=([^&]+)", src)
        return None if m and GIT_REF_OK.fullmatch(m.group(1)) else MESSAGES["version-module-git"]
    if REGISTRY_SOURCE.fullmatch(src):
        ver = mod.get("version")
        value = ver.literal() if ver is not None else None
        ok = isinstance(value, str) and not re.search(r"[<>!]", value) and _pinned(value)
        return None if ok else MESSAGES["version-module-registry"]
    return MESSAGES["version-module-remote"]


def static_credentials(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for b in blocks:
        if b.type == "provider":
            for a in _attrs_deep(b):
                if a.name in PROVIDER_CRED_ATTRS:
                    out.append(_f("static-credentials", irel, a.line,
                                  MESSAGES["static-credentials"].format(name=a.name), b.address()))
        elif b.type == "tfvars":
            for a in b.attrs.values():
                if CRED_NAME.match(a.name) and _literal_secret(a):
                    out.append(_f("static-credentials", irel, a.line,
                                  MESSAGES["static-credentials"].format(name=a.name)))
        elif b.type == "variable" and b.labels and CRED_NAME.match(b.labels[0]):
            d = b.get("default")
            if d is not None and isinstance(d.literal(), str) and d.literal():
                out.append(_f("static-credentials", irel, d.line,
                              MESSAGES["static-credentials"].format(name=b.labels[0]), b.address()))
    return out


def _native(irel: str) -> bool:
    low = irel.lower()
    return low.startswith("native/") and not low.endswith((".tf", ".tf.json") + TFVARS_EXT)


def secrets(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    if _native(irel):
        return _native_secrets(irel, text)
    out: List[Finding] = []
    seen = set()

    def add(line: int, msg: str, res: str) -> None:
        if line not in seen:
            seen.add(line)
            out.append(_f("secrets", irel, line, msg, res))

    for top in blocks:
        res = _addr(top)
        if top.type == "variable" and top.labels and _sensitive_name(top.labels[0]):
            name = top.labels[0]
            sens = top.get("sensitive")
            if not (sens and sens.literal() is True):
                add(top.line, MESSAGES["secrets-variable"].format(name=name), res)
            d = top.get("default")
            if d is not None and _literal_secret(d):
                add(d.line, MESSAGES["secrets-default"].format(name=name), res)
        for attr in (a for b in _walk_blocks([top]) if b.type not in NON_SECRET_BLOCKS for a in b.attrs.values()):
            for name, a, is_obj in _named_values(attr):
                if _sensitive_name(name) and _literal_secret(a, strict=_norm(name) in STRICT_NAMES
                                                             or name.lower().endswith("_wo")):
                    add(a.line, MESSAGES["secrets"], res)
                elif not is_obj and _secret_hit(a.raw):
                    add(a.line, MESSAGES["secrets"], res)
    return out


def required_tags(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    if irel.startswith("modules/"):
        return []
    out: List[Finding] = []
    for p in (b for b in blocks if b.type == "provider" and b.labels[:1] == ["aws"]):
        problems: List[str] = []
        dt = p.children("default_tags")
        tags = dt[0].get("tags") if dt else None
        entries = tags.entries() if tags is not None else None
        if not dt:
            problems.append("default_tags assente")
        elif entries is None:
            problems.append("tags non è un oggetto con chiavi letterali")
        else:
            missing = [t for t in REQUIRED_TAGS if t not in entries]
            if missing:
                problems.append("mancano " + ", ".join(missing))
            mb = entries.get("ManagedBy")
            if mb is not None and mb.literal() != "kynfra":
                problems.append("ManagedBy deve essere \"kynfra\"")
        if problems:
            line = tags.line if tags is not None else (dt[0].line if dt else p.line)
            out.append(_f("required-tags", irel, line, MESSAGES["required-tags"].format(problems="; ".join(problems)),
                          p.address()))
    return out


def account_guard(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    if irel.startswith("modules/"):
        return []
    out: List[Finding] = []
    for p in (b for b in blocks if b.type == "provider" and b.labels[:1] == ["aws"]):
        ids = p.get("allowed_account_ids")
        if ids is None or ids.literal() == []:
            out.append(_f("account-guard", irel, p.line, MESSAGES["account-guard"], p.address()))
    return out


def variables_typed(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for v in (b for b in blocks if b.type == "variable"):
        name = v.labels[0] if v.labels else ""
        if v.get("type") is None:
            out.append(_f("variables-typed", irel, v.line, MESSAGES["variables-type"].format(name=name), v.address()))
        desc = v.get("description")
        if desc is None or desc.literal() == "":
            out.append(_f("variables-typed", irel, v.line, MESSAGES["variables-description"].format(name=name),
                          v.address()))
    return out


def scanner_suppression(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    return [_f("scanner-suppression", irel, i, MESSAGES["scanner-suppression"])
            for i, line in enumerate(text.splitlines(), 1) if SUPPRESS_RE.search(line)]


def no_provisioners(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for top in blocks:
        if top.type == "data" and top.labels[:1] == ["external"]:
            out.append(_f("no-provisioners", irel, top.line,
                          MESSAGES["no-provisioners"].format(what='data "external"'), top.address()))
        for b in _walk_blocks(top.blocks):
            if b.type == "provisioner":
                what = f'provisioner "{b.labels[0]}"' if b.labels else "provisioner"
                out.append(_f("no-provisioners", irel, b.line, MESSAGES["no-provisioners"].format(what=what),
                              top.address()))
    return out


def region_pinning(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    if not irel.startswith("modules/") or irel.lower().endswith(TFVARS_EXT):
        return []
    out: List[Finding] = []
    seen = set()
    for top in (b for b in blocks if b.type != "variable"):
        for a in _attrs_deep(top):
            for key, pat in (("region-pinning-region", REGION_RE), ("region-pinning-account", ACCOUNT_RE)):
                if pat.search(a.raw) and (a.line, key) not in seen:
                    seen.add((a.line, key))
                    out.append(_f("region-pinning", irel, a.line, MESSAGES[key], _addr(top)))
    return out


# ---------------------------------------------------------------- file in native/ (YAML/JSON/Bicep, sul testo)

KV_RE = re.compile(r"""^\s*-?\s*['"]?(?P<k>[A-Za-z_][\w.-]*)['"]?\s*:\s*(?P<v>.*?)\s*,?\s*$""")


def _strip_line_comment(line: str, bicep: bool) -> str:
    return re.sub(r"(^|\s)//.*$" if bicep else r"(^|\s)#.*$", "", line)


def _native_secrets(irel: str, text: str) -> List[Finding]:
    bicep = irel.lower().endswith(".bicep")
    out: List[Finding] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = _strip_line_comment(raw, bicep)
        hit = _secret_hit(line)
        m = KV_RE.match(line)
        if not hit and m and _sensitive_name(m.group("k")):
            raw_v = m.group("v").strip()
            quoted = raw_v[:1] in ("'", '"')
            v = raw_v.strip("'\"")
            if (v and not REFERENCE_VALUE.match(v) and (quoted or not UNQUOTED_REFERENCE.match(v))
                    and len(v) >= 6 and not PLACEHOLDER.match(v)):
                hit = True
        if hit:
            out.append(_f("secrets", irel, i, MESSAGES["secrets"]))
    return out


def _yaml_params(text: str) -> List[Tuple[str, int, dict]]:
    """(nome, riga, proprietà) dei parametri della sezione `Parameters:` di un template CloudFormation YAML."""
    lines = text.splitlines()
    params: List[Tuple[str, int, dict]] = []
    start = next((i for i, l in enumerate(lines) if re.match(r"^Parameters\s*:\s*(#.*)?$", l)), None)
    if start is None:
        return params
    p_indent = prop_indent = None
    for j in range(start + 1, len(lines)):
        line = _strip_line_comment(lines[j], False).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            break
        m = KV_RE.match(line)
        if not m:
            continue
        if p_indent is None:
            p_indent = indent
        if indent == p_indent:
            props: dict = {}
            inline = m.group("v").strip()
            if inline.startswith("{"):
                props = {k: v.strip().strip("'\"") for k, v in re.findall(r"(\w+)\s*:\s*([^,}]+)", inline)}
            params.append((m.group("k"), j + 1, props))
            prop_indent = None
        elif params and indent > p_indent:
            if prop_indent is None:
                prop_indent = indent
            if indent == prop_indent:
                params[-1][2][m.group("k")] = m.group("v").strip().strip("'\"")
    return params


def _json_params(text: str) -> Optional[List[Tuple[str, int, dict]]]:
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("Parameters"), dict):
        return []
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if '"Parameters"' in l), 0)
    out = []
    for name, props in doc["Parameters"].items():
        line = next((i + 1 for i in range(start, len(lines)) if re.search(r'"%s"\s*:' % re.escape(name), lines[i])),
                    start + 1)
        out.append((name, line, {k: v for k, v in props.items()} if isinstance(props, dict) else {}))
    return out


def _bicep_params(irel: str, text: str) -> List[Finding]:
    out: List[Finding] = []
    decorators: List[str] = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = _strip_line_comment(raw, True).strip()
        if not line:
            continue
        if line.startswith("@") and not re.search(r"\bparam\s", line):
            decorators.append(line)
            continue
        m = re.match(r"^((?:@\S+\s+)*)param\s+(\w+)(?:\s+([^=\s]+))?\s*(=.*)?$", line)
        if m:
            name = m.group(2)
            secure = any(d.startswith("@secure") for d in decorators) or "@secure" in m.group(1)
            if not m.group(3):
                out.append(_f("native-params", irel, i, MESSAGES["native-type"].format(name=name)))
            if _sensitive_name(name):
                if not secure:
                    out.append(_f("native-params", irel, i, MESSAGES["native-secure"].format(name=name)))
                if m.group(4):
                    out.append(_f("native-params", irel, i, MESSAGES["native-default"].format(name=name)))
        decorators = []
    return out


def native_params(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    """Parametri dei template nativi: tipizzati; quelli riservati senza default e nascosti (NoEcho / @secure())."""
    low = irel.lower()
    if low.endswith(".bicep"):
        return _bicep_params(irel, text)
    params = _json_params(text) if low.endswith(".json") else _yaml_params(text)
    if params is None:
        return [_f("native-params", irel, 1, MESSAGES["native-json"])]
    out: List[Finding] = []
    for name, line, props in params:
        if "Type" not in props:
            out.append(_f("native-params", irel, line, MESSAGES["native-type"].format(name=name)))
        if _sensitive_name(name):
            if "Default" in props:
                out.append(_f("native-params", irel, line, MESSAGES["native-default"].format(name=name)))
            if str(props.get("NoEcho", "")).lower() != "true":
                out.append(_f("native-params", irel, line, MESSAGES["native-noecho"].format(name=name)))
    return out


COMMON_RULES: List[Callable] = [remote_state, version_pinning, static_credentials, secrets, required_tags,
                                account_guard, variables_typed, scanner_suppression, no_provisioners, region_pinning]
NATIVE_RULES: List[Callable] = [secrets, scanner_suppression, native_params]
