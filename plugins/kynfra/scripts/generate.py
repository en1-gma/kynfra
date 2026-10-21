#!/usr/bin/env python3
"""Generatore deterministico dei pattern di kynfra: copia moduli e stack dai template e compila i tfvars.

Uso: python3 -B generate.py --pattern P [--provider aws] [--env dev,prod] [--var k=v ...] [--force] [--upgrade]
     [--json] [--project DIR]

- `templates/<provider>/modules/<p>/` -> `<infra_root>/modules/<p>/`;
  `templates/<provider>/stacks/<stack>/` -> `<infra_root>/envs/<env>/<stack>/` per ogni ambiente (o
  `envs/shared/<stack>/` se il pattern è `shared`); `templates/<provider>/<dir>/` -> `<infra_root>/<dir>/` una sola
  volta (es. `bootstrap`). `shared_stacks` = [{stack, when}]: stack condivisi copiati una sola volta in
  `envs/shared/<stack>/`, solo se ogni input di `when` ha il valore indicato (es. la zona DNS se `hosted_zone=create`).
  `single_env: true`: un solo ambiente per comando (input come il dominio che cambiano da ambiente ad ambiente).
- I template usano solo segnaposto `{{ nome }}`, senza logica: un segnaposto sconosciuto è un errore.
- Ogni file generato ha in testa `# Generato da kynfra <versione> — pattern <p>` (nessuna intestazione nei JSON).
- Deterministico: nessuna data, iterazione ordinata, un solo a capo in fondo.
- Non sovrascrive i file esistenti (finiscono in "skipped") salvo `--force` e salvo i file `regenerate` del pattern
  (generati dal progetto, es. handlers.auto.tfvars del backend kybes: riscritti a ogni comando, in "regenerated");
  con `--upgrade` non scrive nulla e restituisce le differenze unificate tra i file presenti e quelli che genererebbe
  ora.
- `kybes: {requires_with_workloads}` (pattern backend): i valori degli stack vengono dal progetto kybes
  (`kybes_values`); con microservizi o job i requires si estendono a quei pattern.
Solo libreria standard.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import posixpath
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
             "shared_stacks": [], "single_env": False, "dir": None, "next_steps": [], "kybes": None,
             "regenerate": [], **raw}
    for name, spec in entry["inputs"].items():
        if spec.get("type", "string") not in INPUT_TYPES:
            raise GenerateError(f"input '{name}' del pattern '{pattern}': tipo non supportato")
    for spec in entry["shared_stacks"]:
        if not (isinstance(spec, dict) and isinstance(spec.get("stack"), str) and spec["stack"]
                and isinstance(spec.get("when", {}), dict)
                and all(k in entry["inputs"] for k in spec.get("when", {}))):
            raise GenerateError(f"shared_stacks del pattern '{pattern}' non valido: serve "
                                "{stack: <nome>, when: {<input>: <valore>}} con input del pattern")
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
            pattern: str, prod: Optional[bool] = None) -> Dict[str, str]:
    """Valori degli input: --var, poi env_defaults dell'ambiente, poi il default. `prod` (default: ambiente chiamato
    `prod`) applica a `env` i valori prod-restrittivi di env_defaults["prod"] (ambienti marcati `"prod": true`)."""
    out: Dict[str, str] = {}
    by_env = entry.get("env_defaults") or {}
    if prod is None:
        prod = env == "prod"
    env_defaults = by_env.get("prod", {}) if prod else ({} if env == "prod" else by_env.get(env or "", {}))
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
        choices = spec.get("choices")
        if choices and value not in [_text(c) for c in choices]:
            raise GenerateError(f"'{name}' deve essere uno di: {', '.join(_text(c) for c in choices)} "
                                f"(ricevuto '{value}')")
    return out


# ---------------------------------------------------------------- progetto kybes (pattern backend)

HANDLER_KEY_RE = re.compile(r"[a-z0-9][a-z0-9-]*/(functions|ms)/[a-z0-9][a-z0-9-]*")
JOB_RE = re.compile(r"[a-z0-9][a-z0-9-]*")
ROUTE_PATH_RE = re.compile(r"/[A-Za-z0-9._~{}/+-]*")
WELL_KNOWN = "/.well-known/openid-configuration"


def _hcl(value: Optional[str]) -> str:
    """Stringa HCL letterale (o null) per i tfvars generati: niente interpolazioni né segnaposto."""
    if value is None:
        return "null"
    if any(t in value for t in ("${", "%{", "{{", "}}")) or any(ord(c) < 32 for c in value):
        raise GenerateError(f"valore non ammesso nei tfvars generati: {value!r}")
    return json.dumps(value, ensure_ascii=False)


def _hcl_map(name: str, entries: List[Tuple[str, str]]) -> str:
    """`name = { "chiave" = valore … }` con gli `=` allineati come `terraform fmt`."""
    if not entries:
        return f"{name} = {{}}"
    width = max(len(_hcl(k)) for k, _ in entries)
    body = "\n".join(f"  {_hcl(k).ljust(width)} = {v}" for k, v in entries)
    return f"{name} = {{\n{body}\n}}"


def _oidc_issuer(openapi: Path) -> str:
    """Issuer dagli schemi openIdConnect dello schema OpenAPI (openIdConnectUrl senza /.well-known/…); "" se assente
    o se gli schemi indicano issuer diversi."""
    import mini_yaml
    try:
        doc = mini_yaml.load(openapi.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return ""
    schemes = ((doc.get("components") or {}).get("securitySchemes") or {}) if isinstance(doc, dict) else {}
    found = set()
    for sc in schemes.values() if isinstance(schemes, dict) else []:
        url = sc.get("openIdConnectUrl") if isinstance(sc, dict) and sc.get("type") == "openIdConnect" else None
        if isinstance(url, str) and url.startswith("https://"):
            found.add(url[:-len(WELL_KNOWN)] if url.endswith(WELL_KNOWN) else url.rstrip("/"))
    return found.pop() if len(found) == 1 else ""


def kybes_values(proj: Path, cfg: dict) -> Dict[str, str]:
    """Valori del contesto ricavati dal progetto kybes (spec 6.2) per il pattern backend: il contenuto di
    `handlers.auto.tfvars` (`kybes_handlers`: handlers, routes, public_routes), di `jobs.auto.tfvars` (`kybes_jobs`)
    e di `kybes.auto.tfvars` (radice kybes relativa allo stack `kybes_root`, schema `kybes_openapi`, `kybes_has_db`),
    più i dati per requires e passi successivi (`kybes_has_workloads`, `kybes_repositories`, `kybes_oidc_issuer`,
    `kybes_unapproved_public`, `kybes_no_runtime`, separati da virgola). Operazioni ambigue o handler inesistenti
    sono un errore: kynfra non inventa mai un handler."""
    import kybes
    import rules_aws
    conf = cfg.get("kybes")
    if not conf:
        raise GenerateError(f"il pattern backend legge un progetto kybes, ma {rules.CONFIG_REL} non ha la sezione "
                            "kybes: l'utente la aggiunge ({\"kybes\": {\"root\": \".\"}}) o reinstalla kynfra nel "
                            "repository kybes")
    conf = conf if isinstance(conf, dict) else {}
    root_rel = rules._normalize_infra_root(conf.get("root"))
    openapi = rules._normalize_infra_root(conf.get("openapi") or "schemas/openapi.yaml")
    if openapi == ".":
        openapi = "schemas/openapi.yaml"
    kroot = proj / root_rel
    try:
        p = kybes.read_project(kroot, openapi)
        schedules = {j: kybes.job_schedule(kroot, j) for j in p.jobs}
    except kybes.KybesError as e:
        raise GenerateError(f"progetto kybes non leggibile ({posixpath.join(root_rel, openapi)}): {e}")
    mapping, unresolved = kybes.resolve_mapping(p)
    if unresolved:
        raise GenerateError("operazioni senza handler deducibile (contesto con più handler o fuori dalla convenzione "
                            "/v1/<contesto>/...): " + ", ".join(op.route for op in unresolved) + ". Chiedi all'utente "
                            "l'handler di ognuna e aggiungi x-kybes-handler: <contesto>/functions/<nome> (o /ms/<nome>) "
                            "all'operazione in " + openapi)
    missing = sorted(f"{r} -> {h}" for r, h in mapping.items() if h not in p.handlers)
    if missing:
        raise GenerateError("operazioni mappate su handler che non esistono in services/: " + ", ".join(missing))
    for key in p.handlers:
        if not HANDLER_KEY_RE.fullmatch(key):
            raise GenerateError(f"handler '{key}': contesti e nomi in services/ devono essere in kebab-case minuscolo")
    for job in p.jobs:
        if not JOB_RE.fullmatch(job):
            raise GenerateError(f"job '{job}': i nomi in jobs/ devono essere in kebab-case minuscolo")
    # ruoli Pod Identity, service account e repository ECR: <contesto>-<nome> per i microservizi, <nome> per i job
    clash = sorted(set(p.jobs) & {k.replace("/ms/", "-") for k, h in p.handlers.items() if h.kind == "ms"})
    if clash:
        raise GenerateError("job con lo stesso nome di un microservizio (<contesto>-<nome>): " + ", ".join(clash)
                            + "; ruoli Pod Identity, service account e repository ECR collidono, rinomina il job")
    for op in p.operations:
        if not ROUTE_PATH_RE.fullmatch(op.path):
            raise GenerateError(f"percorso OpenAPI non supportato: '{op.path}'")
    pub = rules_aws._public_routes(cfg)
    public = [op.route for op in p.operations if op.public]
    approved = [op.route for op in p.operations
                if op.public and ((op.method, op.path) in pub or ("ANY", op.path) in pub)]
    handlers = []
    for key, h in sorted(p.handlers.items()):
        runtime, handler = (h.runtime, h.handler) if h.kind == "function" else (None, None)
        handlers.append((key, f"{{ kind = {_hcl(h.kind)}, runtime = {_hcl(runtime)}, handler = {_hcl(handler)} }}"))
    routes = [(op.route, _hcl(mapping[op.route])) for op in p.operations]
    pub_list = ", ".join(_hcl(r) for r in approved)
    handlers_tfvars = "\n\n".join([_hcl_map("handlers", handlers), _hcl_map("routes", routes),
                                    f"public_routes = [{pub_list}]"])
    jobs = [(j, f"{{ trigger = \"schedule\", schedule = {_hcl(sched)} }}" if sched else '{ trigger = "sqs" }')
            for j, sched in sorted(schedules.items())]
    stack_dir = posixpath.join(proj.as_posix(), _infra_prefix(cfg), "envs", "env", "backend")
    ms = [h for h in sorted(p.handlers) if p.handlers[h].kind == "ms"]
    return {
        "kybes_handlers": handlers_tfvars,
        "kybes_jobs": _hcl_map("jobs", jobs),
        "kybes_root": posixpath.relpath(posixpath.normpath(posixpath.join(proj.as_posix(), root_rel)), stack_dir),
        "kybes_openapi": _check_value("kybes.openapi", openapi),
        "kybes_has_db": "true" if p.has_db else "false",
        "kybes_has_workloads": "true" if (ms or p.jobs) else "false",
        "kybes_repositories": ",".join([m.replace("/ms/", "-") for m in ms] + sorted(p.jobs)),
        "kybes_oidc_issuer": _oidc_issuer(kroot / openapi),
        "kybes_unapproved_public": ",".join(r for r in public if r not in approved),
        "kybes_no_runtime": ",".join(k for k, h in sorted(p.handlers.items())
                                     if h.kind == "function" and not (h.runtime and h.handler)),
    }


def _kybes_steps(kv: Dict[str, str], values: Dict[str, str]) -> List[str]:
    """Passi per il DevOps che dipendono dal progetto kybes."""
    steps: List[str] = []
    if values.get("authorizer", "lambda") == "lambda" and not values.get("oidc_audience"):
        steps.append("authorizer=lambda senza oidc_audience: indica l'audience attesa nei token (--var oidc_audience=… "
                     "o nei terraform.tfvars dello stack), altrimenti il plan fallisce")
    if kv["kybes_no_runtime"]:
        steps.append("Function senza runtime o handler deducibile dal manifest (package.json engines.node e main, "
                     "pyproject.toml requires-python e handler.py/app.py): " + kv["kybes_no_runtime"].replace(",", ", ")
                     + "; completa il manifest e rigenera, altrimenti il plan fallisce")
    if kv["kybes_unapproved_public"]:
        steps.append("Operazioni con security: [] che restano dietro l'authorizer perché non sono in public_routes di "
                     ".kynfra/config.json: " + kv["kybes_unapproved_public"].replace(",", ", ") + "; se sono davvero "
                     "pubbliche l'utente le aggiunge a public_routes e si rigenera")
    if kv["kybes_has_workloads"] == "true":
        steps.append("Microservizi e job girano su EKS: servono lo stack kubernetes (con kubernetes-addons) dello stesso "
                     "ambiente e i repository ECR nello stack envs/shared/ecr: repositories="
                     + kv["kybes_repositories"])
    if kv["kybes_has_db"] == "true" and not values.get("db_instance_identifier"):
        steps.append("Il progetto ha schemas/db: indica db_instance_identifier (istanza RDS esistente con "
                     "iam_database_authentication_enabled = true e l'utente db_iam_user creato per l'autenticazione IAM: "
                     "GRANT rds_iam in PostgreSQL, IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS' in MySQL/MariaDB) "
                     "con --var o nei terraform.tfvars dello stack, poi ammetti "
                     "nel security group del database la sua porta dal security group db_proxy_security_group_id")
    return steps


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
          values: Dict[str, str], extra: Optional[Dict[str, str]] = None) -> List[Tuple[str, str]]:
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
    if "account" in values and not (entry.get("dir") or entry.get("shared") or _triggered_shared(entry, plain)):
        raise GenerateError(f"--var account vale solo per gli stack condivisi: con questi input il pattern '{pattern}' "
                            "non ne genera (l'account degli stack per ambiente viene da environments in config)")
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
            env_ctx = _merge(base, _inputs(entry, values, env, base, pattern, prod=env in rules.prod_envs(cfg)),
                             _account_context(cfg, base, account),
                             {"environment": env}, extra or {})
            for stack in stacks:
                ctx = _merge(env_ctx, {"stack": stack, "state_key": f"{base['project']}/{env}/{stack}.tfstate"})
                add(tpl / "stacks" / stack, f"envs/{env}/{stack}", ctx)
    for stack in _triggered_shared(entry, plain):
        account = _default_account(cfg, envs, values)
        key = f"{base['project']}/shared/{stack}.tfstate"
        ctx = _merge(base, _inputs(entry, values, None, base, pattern), _account_context(cfg, base, account),
                     {"environment": "shared", "stack": stack, "state_key": key})
        add(tpl / "stacks" / stack, f"envs/shared/{stack}", ctx)
    if not out:
        raise GenerateError(f"il pattern '{pattern}' non ha template in {tpl}")
    for rel, _ in out:
        why = rules.protected_reason(rel, cfg)
        if why:
            raise GenerateError(f"il template scriverebbe un file protetto ({rel}): {why}")
    return out


def _triggered_shared(entry: dict, inputs: Dict[str, str]) -> List[str]:
    """Stack di `shared_stacks` il cui `when` combacia con gli input (valori senza ambiente)."""
    return [spec["stack"] for spec in entry.get("shared_stacks") or []
            if all(inputs.get(k) == _text(v) for k, v in sorted((spec.get("when") or {}).items()))]


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

    Ritorna {created, regenerated, skipped, diffs, missing_requires, next_steps}: `regenerated` sono i file in
    `regenerate` del pattern (generati dal progetto, es. handlers.auto.tfvars) riscritti anche senza --force."""
    if provider not in (cfg.get("providers") or []):
        raise GenerateError(f"provider '{provider}' non in config (providers: {', '.join(cfg.get('providers') or [])})")
    entry = load_pattern(provider, pattern)
    envs = _validate_envs(cfg, list(envs))
    values = dict(values)
    shared = entry.get("dir") or entry.get("shared") or entry.get("shared_stacks")
    allowed = set(entry["inputs"]) | ({"account"} if shared else set())
    if entry.get("single_env") and len(envs) != 1:
        raise GenerateError(f"il pattern '{pattern}' si genera un ambiente per comando (--env <ambiente>): input come "
                            "il dominio cambiano da ambiente ad ambiente")
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise GenerateError(f"variabili sconosciute per il pattern '{pattern}': {', '.join(unknown)} "
                            f"(ammesse: {', '.join(sorted(allowed)) or 'nessuna'})")
    kv: Dict[str, str] = {}
    if entry.get("kybes"):
        kv = kybes_values(proj, cfg)
        if "oidc_issuer" in entry["inputs"] and not values.get("oidc_issuer") and kv["kybes_oidc_issuer"]:
            values["oidc_issuer"] = kv["kybes_oidc_issuer"]
    files = _plan(cfg, provider, pattern, entry, envs, values, kv)
    regenerate = set(entry.get("regenerate") or [])
    created: List[str] = []
    regenerated: List[str] = []
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
            # file generati dal progetto (es. handlers.auto.tfvars): si rigenerano sempre, non si modificano a mano
            if posixpath.basename(rel) not in regenerate:
                skipped.append(rel)
                continue
            if current == content:
                continue
            regenerated.append(rel)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".kynfra-tmp")
        tmp.write_text(content, encoding="utf-8")
        os.replace(tmp, dest)
        if current is None or force or posixpath.basename(rel) not in regenerate:
            created.append(rel)
    requires = list(entry["requires"])
    if kv.get("kybes_has_workloads") == "true":
        requires += [r for r in (entry["kybes"] or {}).get("requires_with_workloads", []) if r not in requires]
    missing = [r for r in requires if not _present(proj, cfg, provider, r, envs)]
    summary = _merge(_base_context(cfg, pattern, provider), {"envs": ",".join(envs)})
    try:
        summary = _merge(summary, _account_context(cfg, summary, _default_account(cfg, envs, values)))
    except GenerateError:
        pass
    next_steps = [render(s, summary) for s in entry.get("next_steps") or []]
    if kv:
        next_steps = _kybes_steps(kv, values) + next_steps
    if missing:
        next_steps.insert(0, "Genera prima i pattern richiesti: " + ", ".join(missing))
    return {"created": sorted(created), "regenerated": sorted(regenerated), "skipped": sorted(skipped),
            "diffs": dict(sorted(diffs.items())), "missing_requires": missing, "next_steps": next_steps}


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
    for title, key in (("File creati", "created"), ("File rigenerati dal progetto", "regenerated"),
                       ("File esistenti non sovrascritti (usa --force)", "skipped")):
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
