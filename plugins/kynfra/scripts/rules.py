"""Regole di kynfra: configurazione, scoperta del progetto, struttura delle cartelle e file protetti.

Usato dagli hook (pre_write, post_edit, stop_gate) e da arch_check. Solo libreria standard.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

CONFIG_REL = ".kynfra/config.json"

# Le regole oltre la base sono implementate nei task successivi; i nomi sono fissi.
DEFAULT_RULES: Dict[str, str] = {
    "protected-files": "block",
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


def normalize_config(raw: dict) -> dict:
    cfg = dict(raw)
    cfg["iac"] = raw.get("iac") if raw.get("iac") in ("terraform", "opentofu") else "terraform"
    cfg["providers"] = list(raw.get("providers") or ["aws"])
    cfg["infra_root"] = (str(raw.get("infra_root") or ".").strip("/") or ".")
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
]


def protected_reason(rel: str, cfg: Optional[dict] = None) -> Optional[str]:
    low = rel.lower()
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
