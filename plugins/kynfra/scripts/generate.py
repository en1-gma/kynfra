#!/usr/bin/env python3
"""Generatore deterministico dei pattern di kynfra: copia moduli e stack dai template e compila i tfvars.

Uso: python3 -B generate.py --pattern P [--provider aws] [--env dev,prod] [--var k=v ...] [--force] [--upgrade]
     [--json] [--project DIR]

- `templates/<provider>/modules/<p>/` -> `<infra_root>/modules/<p>/`;
  `templates/<provider>/stacks/<stack>/` -> `<infra_root>/envs/<env>/<stack>/` per ogni ambiente (o
  `envs/shared/<stack>/` se il pattern è `shared`); `templates/<provider>/<dir>/` -> `<infra_root>/<dir>/` una sola
  volta (es. `bootstrap`).
- I template usano solo segnaposto `{{ nome }}`, senza logica: un segnaposto sconosciuto è un errore.
- Ogni file generato ha in testa `# Generato da kynfra <versione> — pattern <p>` (nessuna intestazione nei JSON).
- Deterministico: nessuna data, iterazione ordinata, un solo a capo in fondo.
- Non sovrascrive i file esistenti (finiscono in "skipped") salvo `--force`; con `--upgrade` non scrive nulla e
  restituisce le differenze unificate tra i file presenti e quelli che genererebbe ora.
Solo libreria standard.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules  # noqa: E402

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
PLUGIN_JSON = Path(__file__).resolve().parent.parent / ".claude-plugin" / "plugin.json"

# Unico punto dei segnaposto di versione: nome -> (chiave di versions.json, forma). La chiave None indica lo
# strumento IaC della config (terraform o opentofu). "constraint" = "~> MAJOR.MINOR", "exact" = versione intera.
VERSION_PLACEHOLDERS: Dict[str, Tuple[Optional[str], str]] = {
    "tf_version_constraint": (None, "constraint"),
    "aws_provider_constraint": ("aws_provider", "constraint"),
    "helm_provider_constraint": ("helm_provider", "constraint"),
    "random_provider_constraint": ("random_provider", "constraint"),
    "aws_load_balancer_controller_chart_version": ("aws_load_balancer_controller_chart", "exact"),
    "karpenter_chart_version": ("karpenter_chart", "exact"),
    "keda_chart_version": ("keda_chart", "exact"),
}

PLACEHOLDER = re.compile(r"\{\{\s*([a-z][a-z0-9_]*)\s*\}\}")
INPUT_TYPES = ("string", "bool", "number")
NUMBER_RE = re.compile(r"-?\d+(\.\d+)?")
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
ACCOUNT_RE = re.compile(r"\d{12}")
REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d")
UNSAFE = ('"', "\\", "${", "%{", "{{", "}}")
# chiavi del contesto fuori da quelle di base e di versione: gli input dei pattern non possono usarle
CONTEXT_KEYS = ("account", "account_id", "state_bucket", "environment", "stack", "state_key", "envs")


class GenerateError(Exception):
    """Errore d'uso o di template: il messaggio è già per l'utente."""


# ---------------------------------------------------------------- dati del kit

def _read_json(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise GenerateError(f"file del kit non leggibile: {path} ({e})")
    if not isinstance(data, dict):
        raise GenerateError(f"file del kit non valido: {path}")
    return data


def kit_version() -> str:
    return str(_read_json(PLUGIN_JSON).get("version") or "0.0.0")


def load_pattern(provider: str, pattern: str) -> dict:
    """Voce di templates/<provider>/patterns.json, con i campi opzionali completati."""
    path = TEMPLATES / provider / "patterns.json"
    if not path.is_file():
        raise GenerateError(f"provider '{provider}' senza pattern ({path} non trovato)")
    data = _read_json(path)
    names = sorted(k for k in data if not k.startswith("_"))
    if pattern.startswith("_") or pattern not in data:
        raise GenerateError(f"pattern '{pattern}' sconosciuto per {provider} (disponibili: {', '.join(names)})")
    raw = data[pattern]
    entry = {"description": "", "requires": [], "inputs": {}, "env_defaults": {}, "stacks": [], "shared": False,
             "dir": None, "next_steps": [], **raw}
    for name, spec in entry["inputs"].items():
        if spec.get("type", "string") not in INPUT_TYPES:
            raise GenerateError(f"input '{name}' del pattern '{pattern}': tipo non supportato")
    return entry


def version_context(iac: str) -> Dict[str, str]:
    """Segnaposto di versione (VERSION_PLACEHOLDERS) dai valori di versions.json."""
    versions = _read_json(TEMPLATES / "versions.json")
    tool = "opentofu" if iac == "opentofu" else "terraform"
    out: Dict[str, str] = {}
    for name, (key, form) in sorted(VERSION_PLACEHOLDERS.items()):
        ver = str((versions.get(key or tool) or {}).get("version", ""))
        m = VERSION_RE.fullmatch(ver)
        if not m:
            raise GenerateError(f"versione di '{key or tool}' non valida in versions.json: '{ver}'")
        out[name] = f"~> {m.group(1)}.{m.group(2)}" if form == "constraint" else ver
    return out


# ---------------------------------------------------------------- rendering

def render(text: str, ctx: Dict[str, str]) -> str:
    """Sostituisce i segnaposto `{{ nome }}`; un nome sconosciuto o un `{{` residuo è un errore."""
    unknown = sorted({m.group(1) for m in PLACEHOLDER.finditer(text) if m.group(1) not in ctx})
    if unknown:
        raise GenerateError(f"segnaposto sconosciuti nel template: {', '.join(unknown)}")
    out = PLACEHOLDER.sub(lambda m: ctx[m.group(1)], text)
    if "{{" in out:
        raise GenerateError("segnaposto malformato nel template (resta '{{' dopo il rendering)")
    return out


def _header(rel: str, pattern: str, version: str) -> str:
    low = rel.lower()
    if low.endswith(".json"):
        return ""
    line = f"Generato da kynfra {version} — pattern {pattern}"
    return f"<!-- {line} -->\n" if low.endswith(".md") else f"# {line}\n"


def _render_file(src: Path, rel: str, ctx: Dict[str, str], pattern: str, version: str) -> str:
    try:
        text = src.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise GenerateError(f"template non UTF-8: {src}")
    body = render(text, ctx).rstrip("\n") + "\n"
    return _header(rel, pattern, version) + body


def _template_files(src_dir: Path) -> List[Path]:
    """File dei template in ordine stabile, esclusi i file e le cartelle nascosti (.DS_Store, .terraform, …)."""
    if not src_dir.is_dir():
        return []
    files = (p for p in src_dir.rglob("*")
             if p.is_file() and not any(part.startswith(".") for part in p.relative_to(src_dir).parts))
    return sorted(files, key=lambda p: p.relative_to(src_dir).as_posix())


def _merge(*parts: Dict[str, str]) -> Dict[str, str]:
    """Unione dei pezzi di contesto; una chiave presente in due pezzi è un errore (nessuna sovrascrittura muta)."""
    out: Dict[str, str] = {}
    for part in parts:
        clash = sorted(set(out) & set(part))
        if clash:
            raise GenerateError(f"chiavi di contesto in conflitto: {', '.join(clash)}")
        out.update(part)
    return out


# ---------------------------------------------------------------- valori

def _check_value(name: str, value: str, kind: str = "string") -> str:
    if kind == "bool":
        if value not in ("true", "false"):
            raise GenerateError(f"'{name}' deve essere true o false (ricevuto '{value}')")
    elif kind == "number":
        if not NUMBER_RE.fullmatch(value):
            raise GenerateError(f"'{name}' deve essere un numero (ricevuto '{value}')")
    elif any(ch in value for ch in UNSAFE) or any(ord(c) < 32 for c in value):
        raise GenerateError(f"valore di '{name}' non ammesso: niente virgolette, backslash, a capo, "
                            "'${', '%{', '{{', '}}'")
    return value


def _text(value) -> str:
    """Valore JSON di un input (default o env_defaults) come testo: i booleani diventano true/false."""
    return str(value).lower() if isinstance(value, bool) else str(value)


def _account_id(cfg: dict, name: str) -> str:
    acc = (cfg.get("accounts") or {}).get(name)
    acc_id = str((acc or {}).get("id", "")) if isinstance(acc, dict) else ""
    if not ACCOUNT_RE.fullmatch(acc_id) or acc_id == "000000000000":
        raise GenerateError(f"account '{name}' senza ID valido (12 cifre): compila accounts.{name}.id in "
                            f"{rules.CONFIG_REL}")
    return acc_id


def _env_account(cfg: dict, env: str) -> str:
    e = cfg["environments"].get(env) or {}
    return str(e.get("account") or "main") if isinstance(e, dict) else "main"


def _base_context(cfg: dict, pattern: str, provider: str) -> Dict[str, str]:
    project = str(cfg.get("project") or "")
    if not rules.KEBAB.fullmatch(project):
        raise GenerateError(f"project '{project}' non valido: serve un nome kebab-case in {rules.CONFIG_REL}")
    region = str(cfg.get("region") or "")
    if not REGION_RE.fullmatch(region):
        raise GenerateError(f"region '{region}' non valida in {rules.CONFIG_REL}")
    tags = cfg.get("tags") or {}
    ctx = {"project": project, "region": region, "pattern": pattern, "provider": provider,
           "kynfra_version": kit_version(), "infra_root": cfg.get("infra_root", "."),
           "iac_cli": "tofu" if cfg.get("iac") == "opentofu" else "terraform"}
    for tag, key in (("Owner", "owner"), ("CostCenter", "cost_center")):
        value = str(tags.get(tag) or "").strip()
        if not value:
            raise GenerateError(f"tag {tag} vuoto: compila tags.{tag} in {rules.CONFIG_REL}")
        ctx[key] = _check_value(f"tags.{tag}", value)
    ctx.update(version_context(cfg.get("iac", "terraform")))
    return ctx


def _account_context(cfg: dict, ctx: Dict[str, str], account: str) -> Dict[str, str]:
    acc_id = _account_id(cfg, account)
    return {"account": account, "account_id": acc_id, "state_bucket": f"{ctx['project']}-tfstate-{acc_id}"}


def _inputs(entry: dict, values: Dict[str, str], env: Optional[str], base: Dict[str, str],
            pattern: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    env_defaults = (entry.get("env_defaults") or {}).get(env or "", {})
    for name, spec in sorted(entry["inputs"].items()):
        if name in base or name in CONTEXT_KEYS:
            raise GenerateError(f"input '{name}' del pattern '{pattern}' ha un nome riservato")
        if name in values:
            value = values[name]
        elif name in env_defaults:
            value = _text(env_defaults[name])
        elif "default" in spec and spec["default"] is not None:
            value = _text(spec["default"])
        elif spec.get("required", True):
            raise GenerateError(f"manca --var {name}=… ({spec.get('help', 'input richiesto')})")
        else:
            continue  # facoltativo senza default: fuori dal contesto (un template che lo usa è un errore)
        out[name] = _check_value(name, value, spec.get("type", "string"))
    return out


# ---------------------------------------------------------------- piano dei file

def _infra_prefix(cfg: dict) -> str:
    root = cfg.get("infra_root", ".")
    return "" if root in ("", ".") else root + "/"


def _default_account(cfg: dict, envs: List[str], values: Dict[str, str]) -> str:
    if values.get("account"):
        return values["account"]
    accounts = sorted({_env_account(cfg, e) for e in (envs or sorted(cfg["environments"]))})
    if len(accounts) != 1:
        raise GenerateError(f"più account negli ambienti ({', '.join(accounts)}): indica --var account=<nome>")
    return accounts[0]


def _plan(cfg: dict, provider: str, pattern: str, entry: dict, envs: List[str],
          values: Dict[str, str]) -> List[Tuple[str, str]]:
    """[(percorso relativo al progetto, contenuto)] dei file del pattern."""
    base = _base_context(cfg, pattern, provider)
    version = base["kynfra_version"]
    prefix = _infra_prefix(cfg)
    tpl = TEMPLATES / provider
    out: List[Tuple[str, str]] = []

    def add(src_dir: Path, dest_rel: str, ctx: Dict[str, str]) -> None:
        for src in _template_files(src_dir):
            rel = f"{prefix}{dest_rel}/{src.relative_to(src_dir).as_posix()}"
            out.append((rel, _render_file(src, rel, ctx, pattern, version)))

    plain = _merge(base, _inputs(entry, values, None, base, pattern))
    add(tpl / "modules" / pattern, f"modules/{pattern}", plain)
    if entry.get("dir"):
        account = _default_account(cfg, envs, values)
        add(tpl / entry["dir"], entry["dir"], _merge(plain, _account_context(cfg, base, account)))
    stacks = list(entry.get("stacks") or [])
    if stacks:
        targets = ["shared"] if entry.get("shared") else list(envs)
        if not targets:
            raise GenerateError(f"il pattern '{pattern}' ha stack per ambiente: indica --env <ambiente>[,<ambiente>]")
        for env in targets:
            account = _default_account(cfg, envs, values) if env == "shared" else _env_account(cfg, env)
            env_ctx = _merge(base, _inputs(entry, values, env, base, pattern), _account_context(cfg, base, account),
                             {"environment": env})
            for stack in stacks:
                ctx = _merge(env_ctx, {"stack": stack, "state_key": f"{base['project']}/{env}/{stack}.tfstate"})
                add(tpl / "stacks" / stack, f"envs/{env}/{stack}", ctx)
    if not out:
        raise GenerateError(f"il pattern '{pattern}' non ha template in {tpl}")
    for rel, _ in out:
        why = rules.protected_reason(rel, cfg)
        if why:
            raise GenerateError(f"il template scriverebbe un file protetto ({rel}): {why}")
    return out


def _present(proj: Path, cfg: dict, provider: str, name: str, envs: List[str]) -> bool:
    entry = load_pattern(provider, name)
    root = proj / _infra_prefix(cfg) if _infra_prefix(cfg) else proj
    if entry.get("dir"):
        return (root / entry["dir"]).is_dir()
    stacks = entry.get("stacks") or []
    if stacks:
        targets = ["shared"] if entry.get("shared") else envs
        if targets:
            return all((root / "envs" / env / s).is_dir() for env in targets for s in stacks)
    return (root / "modules" / name).is_dir()


# ---------------------------------------------------------------- generazione

def _validate_envs(cfg: dict, envs: List[str]) -> List[str]:
    out: List[str] = []
    for e in envs:
        e = e.strip()
        if not e:
            continue
        if e not in cfg["environments"]:
            raise GenerateError(f"ambiente '{e}' non in config (ammessi: {', '.join(sorted(cfg['environments']))})")
        if e not in out:
            out.append(e)
    return out


def _inside(proj: Path, rel: str) -> Path:
    dest = proj / rel
    try:
        dest.resolve().relative_to(proj.resolve())
    except ValueError:
        raise GenerateError(f"percorso fuori dal progetto: {rel}")
    return dest


def generate(proj: Path, cfg: dict, provider: str, pattern: str, envs: List[str], values: Dict[str, str],
             force: bool = False, upgrade: bool = False) -> dict:
    """Genera il pattern nel progetto (vedi docstring del modulo).

    Ritorna {created, skipped, diffs, missing_requires, next_steps}."""
    if provider not in (cfg.get("providers") or []):
        raise GenerateError(f"provider '{provider}' non in config (providers: {', '.join(cfg.get('providers') or [])})")
    entry = load_pattern(provider, pattern)
    envs = _validate_envs(cfg, list(envs))
    values = dict(values)
    allowed = set(entry["inputs"]) | ({"account"} if entry.get("dir") or entry.get("shared") else set())
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise GenerateError(f"variabili sconosciute per il pattern '{pattern}': {', '.join(unknown)} "
                            f"(ammesse: {', '.join(sorted(allowed)) or 'nessuna'})")
    files = _plan(cfg, provider, pattern, entry, envs, values)
    created: List[str] = []
    skipped: List[str] = []
    diffs: Dict[str, str] = {}
    for rel, content in files:
        dest = _inside(proj, rel)
        current = dest.read_text(encoding="utf-8", errors="replace") if dest.is_file() else None
        if upgrade:
            if current != content:
                diffs[rel] = "".join(difflib.unified_diff(
                    (current or "").splitlines(keepends=True), content.splitlines(keepends=True),
                    fromfile=f"a/{rel}" if current is not None else "/dev/null", tofile=f"b/{rel}"))
            continue
        if dest.exists() and not force:
            skipped.append(rel)
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".kynfra-tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, dest)
        created.append(rel)
    missing = [r for r in entry["requires"] if not _present(proj, cfg, provider, r, envs)]
    summary = _merge(_base_context(cfg, pattern, provider), {"envs": ",".join(envs)})
    try:
        summary = _merge(summary, _account_context(cfg, summary, _default_account(cfg, envs, values)))
    except GenerateError:
        pass
    next_steps = [render(s, summary) for s in entry.get("next_steps") or []]
    if missing:
        next_steps.insert(0, "Genera prima i pattern richiesti: " + ", ".join(missing))
    return {"created": sorted(created), "skipped": sorted(skipped), "diffs": dict(sorted(diffs.items())),
            "missing_requires": missing, "next_steps": next_steps}


# ---------------------------------------------------------------- CLI

def _parse_vars(items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise GenerateError(f"--var '{item}': serve la forma nome=valore")
        k, v = item.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", k):
            raise GenerateError(f"--var '{item}': nome non valido")
        out[k] = v
    return out


def _print_human(res: dict, upgrade: bool) -> None:
    if upgrade:
        if not res["diffs"]:
            print("kynfra: nessuna differenza rispetto ai template installati")
        for rel, diff in res["diffs"].items():
            print(f"--- differenze in {rel}")
            print(diff, end="" if diff.endswith("\n") else "\n")
        print("kynfra: --upgrade non ha scritto nulla; applica le modifiche che vuoi con gli strumenti di modifica")
    for title, key in (("File creati", "created"), ("File esistenti non sovrascritti (usa --force)", "skipped")):
        if res[key]:
            print(f"{title} ({len(res[key])}):")
            print("\n".join(f"- {r}" for r in res[key]))
    if res["missing_requires"]:
        print("Pattern richiesti mancanti: " + ", ".join(res["missing_requires"]))
    if res["next_steps"]:
        print("Prossimi passi:")
        print("\n".join(f"- {s}" for s in res["next_steps"]))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generatore dei pattern di kynfra")
    ap.add_argument("--pattern", required=True)
    ap.add_argument("--provider", default="aws")
    ap.add_argument("--env", default="", help="ambienti separati da virgola (es. dev,prod)")
    ap.add_argument("--var", action="append", default=[], help="input del pattern, nome=valore (ripetibile)")
    ap.add_argument("--force", action="store_true", help="sovrascrive i file esistenti")
    ap.add_argument("--upgrade", action="store_true", help="mostra le differenze con i template, senza scrivere")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--project", default=None)
    a = ap.parse_args(argv)
    proj = Path(a.project).resolve() if a.project else rules.find_project_dir(os.getcwd())
    cfg = rules.load_config(proj)
    if cfg is None:
        print(f"kynfra: {rules.CONFIG_REL} non trovato in {proj}: esegui prima l'installer", file=sys.stderr)
        return 2
    try:
        res = generate(proj, cfg, a.provider, a.pattern, a.env.split(","), _parse_vars(a.var),
                       force=a.force, upgrade=a.upgrade)
    except GenerateError as e:
        print(f"kynfra: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        _print_human(res, a.upgrade)
    return 0


if __name__ == "__main__":
    sys.exit(main())
