"""Regole di kynfra: configurazione, scoperta del progetto, struttura delle cartelle e file protetti.

Usato dagli hook (pre_write, post_edit, stop_gate) e da arch_check. Solo libreria standard.
"""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

CONFIG_REL = ".kynfra/config.json"

# Le regole oltre la base sono implementate nei task successivi; i nomi sono fissi.
DEFAULT_RULES: Dict[str, str] = {
    "protected-files": "block",
    "config": "warn",
    "folder-layout": "block",
    "hcl-syntax": "block",
    "remote-state": "block",
    "version-pinning": "block",
    "static-credentials": "block",
    "secrets": "block",
    "required-tags": "block",
    "account-guard": "block",
    "scanner-suppression": "block",
    "no-provisioners": "block",
    "native-params": "block",
    "s3-private": "block",
    "cloudfront-https": "block",
    "lb-https": "block",
    "sg-open": "block",
    "iam-least-privilege": "block",
    "kms-rotation": "block",
    "logs-retention": "block",
    "eks-hardening": "block",
    "ecr-hardening": "block",
    "api-hardening": "block",
    "lambda-hardening": "block",
    "api-coverage": "block",
    "variables-typed": "warn",
    "region-pinning": "warn",
    "literal-reuse": "warn",
}

KEBAB = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
IAC_EXT = (".tf", ".tf.json", ".tfvars", ".tfvars.json")
NATIVE_EXT = (".yaml", ".yml", ".json", ".bicep")


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    message: str
    resource: str = ""

    def format(self) -> str:
        loc = f"{self.path}:{self.line}" if self.line else self.path
        res = f" ({self.resource})" if self.resource else ""
        return f"- [{self.rule}] {loc}{res} — {self.message}"


# ---------------------------------------------------------------- configurazione

def nearest_project(start: Path) -> Optional[Path]:
    """Cartella più vicina (start o un suo antenato) che contiene .kynfra/config.json."""
    cur = start.resolve()
    if not cur.is_dir():
        cur = cur.parent
    for d in (cur, *cur.parents):
        if (d / CONFIG_REL).is_file():
            return d
    return None


def find_project_dir(start: Optional[str]) -> Path:
    env = os.environ.get("CLAUDE_PROJECT_DIR") or os.environ.get("KYNFRA_PROJECT_DIR")
    if env and (Path(env) / CONFIG_REL).is_file():
        return Path(env).resolve()
    cur = Path(start or os.getcwd()).resolve()
    found = nearest_project(cur)
    if found:
        return found
    return Path(env).resolve() if env else cur


def project_for_file(path: str, cwd: Optional[str]) -> Path:
    """Progetto kynfra di un file: la config più vicina al file (monorepo), altrimenti quella del cwd."""
    p = Path(path)
    if not p.is_absolute():
        p = Path(cwd or os.getcwd()) / p
    # risale dalla cartella del file anche se il file (o le sue cartelle) non esistono ancora
    probe = p.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return nearest_project(probe) or find_project_dir(cwd)


def discover_projects(root: Path, max_depth: int = 4) -> List[Path]:
    """Progetti kynfra sotto `root` (monorepo aperto nella radice), escluse le dipendenze."""
    found: List[Path] = []
    root = root.resolve()
    for dirpath, dirnames, _ in os.walk(root):
        depth = len(Path(dirpath).relative_to(root).parts)
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git", ".terraform", "dist", "build",
                                                        "tools")] if depth < max_depth else []
        if (Path(dirpath) / CONFIG_REL).is_file():
            found.append(Path(dirpath))
    return found


def load_config(proj: Path) -> Optional[dict]:
    p = proj / CONFIG_REL
    if not p.is_file():
        return None
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    return normalize_config(raw)


def _normalize_infra_root(value) -> str:
    """infra_root relativo e normalizzato; vuoto, assoluto o fuori dal progetto diventa "."."""
    v = str(value or ".").replace("\\", "/")
    if v.startswith("/"):
        return "."
    norm = posixpath.normpath(v)
    if norm in (".", "..") or norm.startswith("../"):
        return "."
    return norm.strip("/") or "."


def normalize_config(raw: dict) -> dict:
    cfg = dict(raw)
    cfg["iac"] = raw.get("iac") if raw.get("iac") in ("terraform", "opentofu") else "terraform"
    cfg["providers"] = list(raw.get("providers") or ["aws"])
    cfg["infra_root"] = _normalize_infra_root(raw.get("infra_root"))
    cfg["project"] = raw.get("project") or ""
    cfg["region"] = raw.get("region") or "eu-south-1"
    cfg["accounts"] = dict(raw.get("accounts") or {})
    cfg["environments"] = dict(raw.get("environments")
                               or {e: {"account": "main"} for e in ("dev", "staging", "prod")})
    cfg["tags"] = dict(raw.get("tags") or {})
    cfg["rules"] = {**DEFAULT_RULES, **(raw.get("rules") or {})}
    cfg["exceptions"] = list(raw.get("exceptions") or [])
    cfg["scanner"] = raw.get("scanner") or "checkov"
    cfg["stop_gate"] = {"enabled": True, "only_if_changes": True, "max_blocks": 3, "commands": [],
                        **(raw.get("stop_gate") or {})}
    cfg["literal_reuse"] = {"max_duplicate_ratio": 0.10, "min_values": 20, **(raw.get("literal_reuse") or {})}
    cfg["exclude"] = list(raw.get("exclude") or []) + ["**/.terraform/**"]
    cfg["kybes"] = raw.get("kybes")
    cfg["public_routes"] = list(raw.get("public_routes") or [])
    return cfg


def canonical_rel(rel: str, proj: Path) -> str:
    """Riporta ogni componente già esistente al nome reale su disco.

    Su filesystem case-insensitive (macOS, Windows) `.Kynfra/config.json` è lo stesso file di `.kynfra/config.json`:
    le regole devono vederlo con il nome vero, non con quello scritto.
    """
    cur = proj
    out: List[str] = []
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    for part in parts:
        name = part
        try:
            entries = os.listdir(cur) if cur.is_dir() else []
        except OSError:
            entries = []
        if part not in entries:
            matches = [e for e in entries if e.lower() == part.lower()]
            # solo se il filesystem tratta davvero i due nomi come lo stesso file
            if len(matches) == 1 and (cur / part).exists() and os.path.samefile(cur / part, cur / matches[0]):
                name = matches[0]
        out.append(name)
        cur = cur / name
    return "/".join(out)


def rel_to_project(path: str, proj: Path) -> Optional[str]:
    p = Path(path)
    if not p.is_absolute():
        p = proj / p
    try:
        rel = p.resolve().relative_to(proj.resolve()).as_posix()
    except ValueError:
        return None
    return canonical_rel(rel, proj.resolve())


def glob_match(rel: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        if pat.endswith("/**") and (rel == pat[:-3] or rel.startswith(pat[:-2])):
            return True
        if pat.startswith("**/") and fnmatch.fnmatch(rel, pat[3:]):
            return True
    return False


# ---------------------------------------------------------------- infra_root e struttura

def infra_rel(rel: str, cfg: dict) -> Optional[str]:
    """Percorso relativo a infra_root; None se il file è fuori da infra_root."""
    root = cfg.get("infra_root", ".")
    if root in ("", "."):
        return rel
    if rel.startswith(root + "/"):
        return rel[len(root) + 1:]
    return None


def is_iac_file(rel: str) -> bool:
    """File IaC (percorso relativo a infra_root): Terraform, tfvars e template nativi sotto native/."""
    low = rel.lower()
    if low.endswith(IAC_EXT):
        return True
    return low.startswith("native/") and low.endswith(NATIVE_EXT)


def stack_of(irel: str) -> Optional[Tuple[str, str]]:
    """(ambiente, stack) di un file in envs/<env>/<stack>/..., altrimenti None."""
    parts = irel.split("/")
    if len(parts) >= 4 and parts[0] == "envs":
        return parts[1], parts[2]
    return None


# ---------------------------------------------------------------- file protetti

# (prefisso o file, motivo): confrontati senza distinzione di maiuscole, sui path canonici.
# hook e config dei sottomoduli (anche la cartella hooks stessa) e config dei worktree collegati
GIT_MODULE_RE = re.compile(r"\.git/(?:modules/.+/(?:hooks(?:/.*)?|config(?:\.worktree)?)"
                           r"|worktrees/[^/]+/config(?:\.worktree)?)$")
PROTECTED_PATHS: List[Tuple[str, str]] = [
    (".kynfra/", "la configurazione, il lock e gli strumenti di kynfra li modifica solo l'utente"),
    ("tools/kynfra/", "il kit versionato di kynfra si aggiorna solo con install.sh"),
    (".codex/hooks.json", "gli hook dell'agente li configura solo l'utente"),
    (".codex/config.toml", "la configurazione dell'agente la modifica solo l'utente"),
    (".codex/agents/kynfra_", "gli agenti di kynfra si aggiornano solo con install.sh"),
    (".claude/settings.json", "le impostazioni dell'agente (hook, permessi) le modifica solo l'utente"),
    (".claude/settings.local.json", "le impostazioni dell'agente (hook, permessi) le modifica solo l'utente"),
    (".claude/rules/kynfra/", "le regole di kynfra si aggiornano solo con install.sh"),
    (".agents/skills/kynfra-", "le skill di kynfra si aggiornano solo con install.sh"),
    (".github/workflows/kynfra-check.yml", "il controllo CI di kynfra lo modifica solo l'utente"),
    (".git/hooks/", "gli hook di git eseguono comandi (anche a ogni commit): li modifica solo l'utente"),
    (".git/config", "la configurazione di git può eseguire comandi (alias, pager, hook): la modifica solo l'utente"),
]


def protected_reason(rel: str, cfg: Optional[dict] = None) -> Optional[str]:
    low = rel.lower()
    if GIT_MODULE_RE.fullmatch(low):
        return "hook e configurazione dei sottomoduli e dei worktree git eseguono comandi: li modifica solo l'utente"
    for prefix, why in PROTECTED_PATHS:
        if low == prefix.rstrip("/") or low.startswith(prefix):
            return why
    if low.rsplit("/", 1)[-1] == ".terraform.lock.hcl" and (cfg is None or infra_rel(rel, cfg) is not None):
        return "il lock dei provider lo rigenera solo `terraform init` (stop gate o utente)"
    return None


def check_protected(rel: str, cfg: dict) -> List[Finding]:
    sev = cfg["rules"].get("protected-files", "block")
    if sev == "off":
        return []
    why = protected_reason(rel, cfg)
    return [Finding("protected-files", sev, rel, 0, why)] if why else []


def check_layout(rel: str, cfg: dict) -> List[Finding]:
    """Layout ammesso sotto infra_root: bootstrap/, modules/<p>/, envs/<env|shared>/<stack>/, native/<p>/."""
    sev = cfg["rules"].get("folder-layout", "block")
    if sev == "off":
        return []
    irel = infra_rel(rel, cfg)
    if irel is None or not is_iac_file(irel):
        return []

    def bad(msg: str) -> List[Finding]:
        return [Finding("folder-layout", sev, rel, 0, msg)]

    parts = irel.split("/")
    top = parts[0]
    if top == "bootstrap" and len(parts) >= 2:
        return []
    if top in ("modules", "native"):
        if len(parts) < 3:
            return bad(f"in {top}/ ogni file sta in una cartella {top}/<pattern>/")
        if not KEBAB.fullmatch(parts[1]):
            return bad(f"nome '{parts[1]}' non kebab-case in {top}/")
        return []
    if top == "envs":
        allowed = sorted(set(cfg["environments"]) | {"shared"})
        if len(parts) < 4:
            return bad("in envs/ ogni file sta in envs/<ambiente>/<stack>/")
        if parts[1] not in allowed:
            return bad(f"ambiente '{parts[1]}' non in config (ammessi: {', '.join(allowed)})")
        if not KEBAB.fullmatch(parts[2]):
            return bad(f"nome di stack '{parts[2]}' non kebab-case")
        return []
    return bad("sotto infra_root sono ammessi solo bootstrap/, modules/<pattern>/, envs/<ambiente>/<stack>/, "
               "native/<pattern>/")


# ---------------------------------------------------------------- contenuto dei file

# Regole dei provider (Task 6+): provider in cfg["providers"] → funzioni (irel, blocks, text, cfg) -> List[Finding].
PROVIDER_RULES: Dict[str, List[Callable]] = {}
# Regole d'insieme dei provider: funzioni (files, cfg) -> List[Finding], con files = [(irel, blocchi)] di una cartella
# Terraform (modules/<p>/, envs/<env>/<stack>/, bootstrap/) o, con `fn.scope == "project"`, dell'intero progetto.
PROVIDER_PROJECT_RULES: Dict[str, List[Callable]] = {}
# modulo che registra le regole del provider in PROVIDER_RULES/PROVIDER_PROJECT_RULES quando viene importato
PROVIDER_MODULES: Dict[str, str] = {"aws": "rules_aws"}


def _load_providers(cfg: dict) -> None:
    import importlib
    for prov in cfg.get("providers") or []:
        mod = PROVIDER_MODULES.get(prov)
        if mod and prov not in PROVIDER_RULES:
            importlib.import_module(mod)


def _rule_name(fn: Callable) -> str:
    return getattr(fn, "__name__", "hcl-syntax").replace("_", "-")


def _parse_exception(e: object) -> Optional[Tuple[dict, date]]:
    """(eccezione, scadenza) se la voce è ben formata (rule, path, reason, expires YYYY-MM-DD), altrimenti None."""
    if not isinstance(e, dict):
        return None
    for key in ("rule", "path", "reason", "expires"):
        if not isinstance(e.get(key), str) or not e[key].strip():
            return None
    try:
        return e, date.fromisoformat(e["expires"].strip())
    except ValueError:
        return None


# Regole di integrità e fail-closed: nessuna eccezione può spegnerle.
NEVER_EXCEPTED = ("hcl-syntax", "protected-files", "config")


def apply_exceptions(findings: List[Finding], cfg: dict, today: Optional[date] = None,
                     report_config: bool = True) -> List[Finding]:
    """Applica le eccezioni di `.kynfra/config.json`. Un'eccezione valida (non scaduta) elimina i finding di `rule`
    il cui percorso (relativo a infra_root) combacia con il glob `path` e, se indicato, con `resource`. Scaduta: il
    finding resta e il messaggio riporta data e motivo. Malformata: ignorata, più un finding `config` (warn) per
    voce, se `report_config`."""
    today = today or date.today()
    valid: List[Tuple[dict, date]] = []
    out: List[Finding] = []
    bad: List[int] = []
    for i, e in enumerate(cfg.get("exceptions") or []):
        parsed = _parse_exception(e)
        if parsed is None:
            bad.append(i)
        else:
            valid.append(parsed)
    for f in findings:
        irel = infra_rel(f.path, cfg)
        expired: Optional[Tuple[dict, date]] = None
        suppressed = False
        if f.rule not in NEVER_EXCEPTED and irel is not None:
            for e, exp in valid:
                if e["rule"] != f.rule or not _glob_match(irel, e["path"].strip()):
                    continue
                if e.get("resource") and e["resource"] != f.resource:
                    continue
                if exp < today:
                    expired = expired or (e, exp)
                else:
                    suppressed = True
                    break
        if suppressed:
            continue
        if expired:
            e, exp = expired
            f.message += f" (eccezione scaduta il {exp.isoformat()}: {e['reason'].strip()})"
        out.append(f)
    sev = cfg["rules"].get("config", "warn")
    if report_config and sev != "off":
        for i in bad:
            out.append(Finding("config", sev, CONFIG_REL, 0,
                               f"eccezione #{i} in exceptions ignorata: servono rule, path, reason ed expires "
                               "(YYYY-MM-DD) validi"))
    return out


def _glob_match(irel: str, pat: str) -> bool:
    pat = pat.lstrip("./") if pat.startswith("./") else pat
    if fnmatch.fnmatch(irel, pat):
        return True
    if pat.endswith("/**") and (irel == pat[:-3] or irel.startswith(pat[:-2])):
        return True
    return pat.startswith("**/") and fnmatch.fnmatch(irel, pat[3:])


def baseline_path() -> Path:
    return Path(__file__).resolve().parent.parent / "templates" / "scanner-baseline.json"


def scanner_baseline(cfg: dict) -> List[dict]:
    """Voci della baseline del kit per lo scanner configurato: {id, envs ("*" o lista), paths (glob relativi a
    infra_root, default ["**"]), reason}. Le voci senza id si ignorano."""
    try:
        data = json.loads(baseline_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: List[dict] = []
    for entry in (data.get(cfg.get("scanner") or "checkov") or []) if isinstance(data, dict) else []:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            continue
        paths = entry.get("paths") or ["**"]
        out.append({"id": entry["id"], "envs": entry.get("envs", "*"),
                    "paths": [p for p in paths if isinstance(p, str)], "reason": str(entry.get("reason") or "")})
    return out


def baseline_allows(baseline: List[dict], check_id: str, irel: str) -> bool:
    """Il controllo fallito `check_id` sul file `irel` (relativo a infra_root) è escluso da una voce della baseline:
    stesso id, file che combacia con uno dei glob `paths`, ambiente dello stack (envs/<env>/…) tra gli `envs` della
    voce. Fuori dagli stack (modules/, bootstrap/) l'ambiente non è noto: valgono solo le voci con envs "*"."""
    key = stack_of(irel)
    env = key[0] if key else None
    for e in baseline:
        if e["id"] != check_id or not any(_glob_match(irel, p) for p in e["paths"]):
            continue
        envs = e["envs"]
        if envs == "*" or (env is not None and isinstance(envs, list) and env in envs):
            return True
    return False


def _post_process(findings: List[Finding], cfg: dict, report_config: bool = True) -> List[Finding]:
    """Severità da cfg["rules"] ("off" elimina il finding), poi le eccezioni dell'utente."""
    out: List[Finding] = []
    for f in findings:
        sev = cfg["rules"].get(f.rule, f.severity)
        if sev == "off":
            continue
        f.severity = sev
        out.append(f)
    return apply_exceptions(out, cfg, report_config=report_config)


def check_content(rel: str, text: str, cfg: dict) -> List[Finding]:
    """Regole sul contenuto di un file IaC (percorso relativo al progetto): sintassi (fail closed), regole comuni,
    regole dei provider in config; [] per file fuori da infra_root o non IaC. I file in native/ (YAML/JSON/Bicep)
    non si leggono come HCL: solo segreti, soppressioni dello scanner e parametri."""
    irel = infra_rel(rel, cfg)
    if irel is None or not is_iac_file(irel):
        return []
    import hcl
    import rules_common

    filename = posixpath.basename(irel).lower()
    findings: List[Finding] = []
    if rules_common._native(irel):
        blocks: list = []
        fns: List[Callable] = list(rules_common.NATIVE_RULES)
    else:
        for line, msg in hcl.parse_problems(text, filename):
            findings.append(Finding("hcl-syntax", "block", irel, line,
                                    f"file non leggibile per intero ({msg}): correggi la sintassi, i guardrail non "
                                    "possono verificare ciò che non leggono"))
        blocks = hcl.parse(text, filename)
        fns = list(rules_common.COMMON_RULES)
        _load_providers(cfg)
        for prov in cfg.get("providers") or []:
            fns.extend(PROVIDER_RULES.get(prov, []))
    for fn in fns:
        try:
            findings.extend(fn(irel, blocks, text, cfg))
        except Exception as e:  # fail closed: una regola che si rompe blocca invece di tacere
            findings.append(Finding(_rule_name(fn), "block", irel, 0,
                                    f"errore interno della regola ({type(e).__name__}): segnala il problema e "
                                    "verifica il file a mano"))
    for f in findings:
        f.path = rel
    return _post_process(findings, cfg, report_config=False)  # il finding `config` lo dà check_project, una volta


# ---------------------------------------------------------------- scansione progetto

def iter_project_files(proj: Path, cfg: dict) -> Iterable[Tuple[str, Path]]:
    """File IaC sotto infra_root (percorsi relativi al progetto), esclusi .terraform/** e `exclude`."""
    root_rel = cfg.get("infra_root", ".")
    root = proj if root_rel in ("", ".") else proj / root_rel
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(proj).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = sorted(d for d in dirnames if d not in (".terraform", ".git", "node_modules")
                             and not glob_match(f"{rel_dir}/{d}/x".lstrip("/"), cfg["exclude"]))
        for fn in sorted(filenames):
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            irel = infra_rel(rel, cfg)
            if irel is None or glob_match(rel, cfg["exclude"]) or not is_iac_file(irel):
                continue
            yield rel, Path(dirpath) / fn


# ---------------------------------------------------------------- regole a livello di progetto

STACK_MESSAGES = {
    "remote-state-none": "stack senza backend remoto: aggiungi backend \"s3\" con encrypt = true e use_lockfile = true "
                         "(chiave <progetto>/<env>/<stack>.tfstate)",
    "remote-state-many": "stack con {n} backend: ne serve esattamente uno (backend \"s3\" cifrato, con lock)",
    "version-required": "stack senza required_version: aggiungi terraform {{ required_version = \"~> X.Y\" }}",
    "required-tags": "stack senza provider \"aws\" con default_tags: aggiungi il provider con i tag obbligatori "
                     "(Project, Environment, Owner, CostCenter, ManagedBy = \"kynfra\")",
    "account-guard": "stack senza provider \"aws\" con allowed_account_ids: aggiungi allowed_account_ids = "
                     "[var.account_id] così un apply sull'account sbagliato fallisce",
}

PORT_ATTRS = {"port", "from_port", "to_port", "container_port", "target_port"}
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
FQDN_RE = re.compile(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", re.I)
NOT_DOMAIN_SUFFIXES = (".tf", ".tfvars", ".json", ".yaml", ".yml", ".py", ".js", ".mjs", ".zip", ".txt", ".sh",
                       ".html", ".css", ".md", ".pem", ".crt", ".tpl", ".bicep", ".jar", ".sql", ".xml")
IGNORED_CIDRS = {"0.0.0.0/0"}
TF_EXT = (".tf", ".tf.json")


def _is_tf(irel: str) -> bool:
    return irel.lower().endswith(TF_EXT)


def _parse_project(proj: Path, cfg: dict) -> List[Tuple[str, str, str, list]]:
    """[(rel, irel, testo, blocchi)] dei file IaC del progetto; i template native/ non hanno blocchi HCL."""
    import hcl
    import rules_common

    out = []
    for rel, path in iter_project_files(proj, cfg):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        irel = infra_rel(rel, cfg) or rel
        blocks = [] if rules_common._native(irel) else hcl.parse(text, posixpath.basename(irel).lower())
        out.append((rel, irel, text, blocks))
    return out


def _group_stacks(parsed) -> Dict[Tuple[str, str], List[Tuple[str, list]]]:
    stacks: Dict[Tuple[str, str], List[Tuple[str, list]]] = {}
    for _, irel, _, blocks in parsed:
        key = stack_of(irel)
        if key is None:
            continue
        entry = stacks.setdefault(key, [])
        if len(irel.split("/")) == 4 and _is_tf(irel):  # solo i file del root module, non le sottocartelle
            entry.append((irel, blocks))
    return stacks


def load_stacks(proj: Path, cfg: dict) -> Dict[Tuple[str, str], List[Tuple[str, list]]]:
    """(ambiente, stack) -> [(percorso relativo a infra_root, blocchi)] dei file .tf di envs/<env>/<stack>/."""
    return _group_stacks(_parse_project(proj, cfg))


def _all_blocks(files: List[Tuple[str, list]]):
    import rules_common
    for _, blocks in files:
        yield from rules_common._walk_blocks(blocks)


def _unit_findings(dir_rel: str, files: List[Tuple[str, list]], cfg: dict, backend: bool) -> List[Finding]:
    """Regole d'insieme su un root module (stack o bootstrap)."""
    out: List[Finding] = []
    top = [b for _, blocks in files for b in blocks]
    terraform = [b for b in top if b.type == "terraform"]
    if backend:
        n = sum(len(t.children("backend")) for t in terraform)
        if n == 0:
            out.append(Finding("remote-state", "block", dir_rel, 0, STACK_MESSAGES["remote-state-none"]))
        elif n > 1:
            out.append(Finding("remote-state", "block", dir_rel, 0, STACK_MESSAGES["remote-state-many"].format(n=n)))
    if not any(t.get("required_version") is not None for t in terraform):
        out.append(Finding("version-pinning", "block", dir_rel, 0, STACK_MESSAGES["version-required"]))
    if "aws" in (cfg.get("providers") or []):
        aws = [b for b in top if b.type == "provider" and b.labels[:1] == ["aws"]]
        if not aws:
            out.append(Finding("required-tags", "block", dir_rel, 0, STACK_MESSAGES["required-tags"]))
            out.append(Finding("account-guard", "block", dir_rel, 0, STACK_MESSAGES["account-guard"]))
    return out


def _stack_findings(parsed, stacks, per_file: List[Finding], cfg: dict) -> List[Finding]:
    root = cfg.get("infra_root", ".")
    prefix = "" if root in ("", ".") else root + "/"
    units: List[Tuple[str, List[Tuple[str, list]], bool]] = []
    for (env, stack), files in sorted(stacks.items()):
        units.append((f"{prefix}envs/{env}/{stack}/", files, True))
    boot = [(irel, blocks) for _, irel, _, blocks in parsed if irel.startswith("bootstrap/") and _is_tf(irel)]
    if boot:
        units.append((f"{prefix}bootstrap/", boot, False))
    out: List[Finding] = []
    for dir_rel, files, backend in units:
        for f in _unit_findings(dir_rel, files, cfg, backend):
            # niente doppioni: se un file dello stack ha già un finding della stessa regola, basta quello
            if any(g.rule == f.rule and g.path.startswith(dir_rel) for g in per_file):
                continue
            out.append(f)
    return out


def _domain_literals(attr, key: str = "", depth: int = 0):
    """(chiave, valore) delle stringhe e interi letterali di un attributo, anche dentro liste e oggetti."""
    if depth > 6:
        return
    entries = attr.entries()
    if entries is not None:
        for k, sub in entries.items():
            yield from _domain_literals(sub, k, depth + 1)
        return
    yield from _flatten(attr.literal(), attr.name if not key else key)


def _flatten(value, key: str):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, str(k))
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _flatten(v, key)
    elif isinstance(value, (str, int)) and not isinstance(value, bool):
        yield key, value


def _domain_value(key: str, value, project: str) -> Optional[str]:
    """Chiave di confronto se il letterale è di dominio (CIDR, FQDN, porta, nome con prefisso progetto)."""
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        port = int(value)
        return f"porta {port}" if key in PORT_ATTRS and 0 < port <= 65535 and port not in (80, 443) else None
    if not isinstance(value, str) or "${" in value or not value:
        return None
    low = value.lower()
    if CIDR_RE.match(value):
        return None if value in IGNORED_CIDRS else value
    if project and low.startswith(project.lower() + "-") and len(value) > len(project) + 1:
        return value
    if FQDN_RE.match(value) and not low.endswith(NOT_DOMAIN_SUFFIXES) and not low.endswith(".amazonaws.com"):
        return value
    return None


def _literal_occurrences(files: List[Tuple[str, list]], cfg: dict) -> Dict[str, List[Tuple[str, int]]]:
    """Letterali di dominio -> posizioni (percorso, riga) in modules/ ed envs/, esclusi i *.tfvars."""
    import rules_common

    project = cfg.get("project") or ""
    occ: Dict[str, List[Tuple[str, int]]] = {}
    for path, blocks in files:
        irel = infra_rel(path, cfg)
        if irel is None or irel.lower().endswith(rules_common.TFVARS_EXT) or \
                irel.split("/")[0] not in ("modules", "envs"):
            continue
        for block in blocks:
            for b in rules_common._walk_blocks([block]):
                if b.type == "backend":
                    continue  # il backend non ammette variabili né locals: il letterale per ambiente è inevitabile
                for attr in b.attrs.values():
                    for key, value in _domain_literals(attr):
                        dv = _domain_value(key, value, project)
                        if dv is not None:
                            occ.setdefault(dv, []).append((path, attr.line))
    return occ


def _reuse_numbers(occ: Dict[str, List[Tuple[str, int]]]):
    dup_values = {v: locs for v, locs in occ.items() if len({p for p, _ in locs}) >= 2}
    total = sum(len(v) for v in occ.values())
    dup = sum(len(v) - 1 for v in dup_values.values())
    top = sorted(((v, len(locs)) for v, locs in dup_values.items()), key=lambda kv: (-kv[1], kv[0]))[:15]
    return total, dup, top, dup_values


def literal_reuse_stats(files: List[Tuple[str, list]], cfg: dict) -> Tuple[int, int, List[Tuple[str, int]]]:
    """(occorrenze di letterali di dominio, occorrenze duplicate, valori più ripetuti come (valore, volte))."""
    total, dup, top, _ = _reuse_numbers(_literal_occurrences(files, cfg))
    return total, dup, top


def literal_reuse(files: List[Tuple[str, list]], cfg: dict, stop_gate: bool = False,
                  stats: Optional[dict] = None) -> List[Finding]:
    """Letterali di dominio ripetuti in più file di modules/ ed envs/ (`files` = [(percorso, blocchi)]).

    Warn per ogni file che ripete un valore già visto in un file precedente; con `stop_gate=True` aggiunge un block se
    la quota di occorrenze duplicate supera la soglia. I valori nei *.tfvars sono definizioni e non si contano.
    Se `stats` è un dict lo riempie con off, total, duplicated, min_values, max_ratio."""
    sev = cfg["rules"].get("literal-reuse", "warn")
    cr = cfg["literal_reuse"]
    if stats is not None:
        stats.update(off=sev == "off", total=0, duplicated=0, min_values=int(cr.get("min_values", 20)),
                     max_ratio=float(cr.get("max_duplicate_ratio", 0.10)))
    if sev == "off":
        return []
    occ = _literal_occurrences(files, cfg)
    total, dup, _, dup_values = _reuse_numbers(occ)
    if stats is not None:
        stats.update(total=total, duplicated=dup)
    out: List[Finding] = []
    for val, locs in dup_values.items():
        first = locs[0][0]
        seen = {first}
        for p, line in locs:
            if p in seen:
                continue
            seen.add(p)
            out.append(Finding("literal-reuse", sev, p, line,
                               f"'{val}' è già scritto in {first}: definiscilo una volta in locals o in una variabile "
                               "(tfvars per i valori di ambiente) e referenzialo"))
    if stop_gate:
        if total >= int(cr.get("min_values", 20)) and total:
            ratio = dup / total
            limit = float(cr.get("max_duplicate_ratio", 0.10))
            if ratio > limit:
                worst = sorted(dup_values.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:15]
                detail = "\n".join(
                    f"    '{v}' ×{len(locs)}: {', '.join(f'{p}:{ln}' for p, ln in locs[:4])}"
                    f"{' …' if len(locs) > 4 else ''}" for v, locs in worst)
                root = cfg.get("infra_root", ".")
                out.append(Finding("literal-reuse", "block", root if root else ".", 0,
                                   f"{ratio:.1%} delle occorrenze di letterali di dominio è duplicato ({dup} su "
                                   f"{total}), soglia {limit:.0%}: definisci ogni valore una volta (locals o "
                                   f"variabili) e referenzialo. Più ripetuti:\n{detail}", "ratio"))
    return out


def _provider_project_findings(parsed, cfg: dict) -> List[Finding]:
    """Regole d'insieme dei provider in config, per cartella Terraform (o sull'intero progetto se `scope` è
    "project"). I percorsi dei finding tornano relativi al progetto."""
    import rules_common

    _load_providers(cfg)
    fns: List[Callable] = []
    for prov in cfg.get("providers") or []:
        fns.extend(PROVIDER_PROJECT_RULES.get(prov, []))
    if not fns:
        return []
    files = [(irel, blocks) for _, irel, _, blocks in parsed if not rules_common._native(irel)]
    dirs: Dict[str, List[Tuple[str, list]]] = {}
    for irel, blocks in files:
        if irel.split("/")[0] in ("modules", "envs", "bootstrap"):
            dirs.setdefault(posixpath.dirname(irel), []).append((irel, blocks))
    root = cfg.get("infra_root", ".")
    prefix = "" if root in ("", ".") else root + "/"
    out: List[Finding] = []
    for fn in fns:
        groups = [("", files)] if getattr(fn, "scope", "dir") == "project" else sorted(dirs.items())
        for d, group in groups:
            try:
                found = fn(group, cfg)
            except Exception as e:  # fail closed, come in check_content: un finding per ogni regola coperta
                names = getattr(fn, "rules", None) or (getattr(fn, "rule", _rule_name(fn)),)
                found = [Finding(name, "block", (d + "/") if d else ".", 0,
                                 f"errore interno della regola ({type(e).__name__}): segnala il problema e "
                                 "verifica i file a mano") for name in names]
            for f in found:
                f.path = prefix + f.path if f.path != "." else (root or ".")
            out.extend(found)
    return out


def check_project(proj: Path, cfg: dict, stop_gate: bool = False, stats: Optional[dict] = None) -> List[Finding]:
    """Controlli sull'intero progetto: check_content su ogni file IaC, regole d'insieme per stack e bootstrap,
    regole d'insieme dei provider (es. rules_aws.AWS_PROJECT_RULES), literal-reuse (con la soglia bloccante solo se
    `stop_gate`). Percorsi relativi al progetto. Se `stats` è un dict lo riempie con i numeri di literal-reuse."""
    parsed = _parse_project(proj, cfg)
    per_file: List[Finding] = []
    for rel, _, text, _ in parsed:
        per_file.extend(check_content(rel, text, cfg))
    extra = _stack_findings(parsed, _group_stacks(parsed), per_file, cfg)
    extra.extend(_provider_project_findings(parsed, cfg))
    reuse = literal_reuse([(rel, blocks) for rel, _, _, blocks in parsed], cfg, stop_gate, stats)
    out = per_file + _post_process(extra, cfg)  # unico punto che segnala le eccezioni malformate
    for f in _post_process(reuse, cfg, report_config=False):
        if f.resource == "ratio":  # la quota oltre soglia blocca sempre (se la regola non è off)
            f.severity = "block"
        out.append(f)
    return out
