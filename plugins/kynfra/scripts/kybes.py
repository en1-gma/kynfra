"""Lettore dei progetti kybes e regola `api-coverage` (spec 6.2). Solo libreria standard.

Contratto di kybes (sola lettura):
- `schemas/openapi.yaml` (o `.json`): le operazioni. L'handler di un'operazione è l'estensione
  `x-kybes-handler: <contesto>/functions/<nome>` (o `<contesto>/ms/<nome>`), che se presente deve essere una stringa
  non vuota. `Operation.public` è vero solo per un `security: []` letterale sull'operazione (non per la sicurezza
  globale vuota o assente). Path item con `$ref` e `x-amazon-apigateway-any-method` non sono supportati: errore.
- `services/<contesto>/functions/<nome>` (Lambda) e `services/<contesto>/ms/<nome>` (microservizi su EKS).
- `jobs/<nome>` (Job KEDA / cron); `schemas/db/<Tabella>.yaml` (modello dati → RDS Proxy).

Mappatura endpoint → handler (`resolve_mapping`): 1) `x-kybes-handler`; 2) convenzione `/v1/<contesto>/...` (il
prefisso di versione `/vN` è facoltativo, se la versione sta in `servers`) quando il contesto ha un solo handler;
altrimenti l'operazione è ambigua e va confermata dall'utente: kynfra non inventa mai un handler.

File generati dal comando backend in `envs/<env>/backend/` (non scritti a mano; formato fisso, letto qui):

    # handlers.auto.tfvars
    handlers = {
      "<contesto>/functions/<nome>" = { kind = "function", runtime = "nodejs20.x", handler = "dist/index.handler" }
      "<contesto>/ms/<nome>"        = { kind = "ms", runtime = null, handler = null }
    }
    routes = {
      "GET /v1/<contesto>/..." = "<chiave di handlers>"   # una voce per operazione OpenAPI: "METODO percorso"
    }

    # jobs.auto.tfvars
    jobs = {
      "<nome>" = { trigger = "sqs" }   # oppure { trigger = "schedule", schedule = "cron(...)" }
    }

    Il trigger di un job è "schedule" se `jobs/<nome>/job.yaml` ha la chiave `schedule` (`job_schedule`), altrimenti
    "sqs". `handlers.auto.tfvars` contiene anche `public_routes = [...]`: le operazioni con `security: []` approvate in
    `public_routes` della config (le altre restano dietro l'authorizer).

`api-coverage` (block, solo con `kybes` in config e lo schema OpenAPI presente) confronta il progetto con ogni stack
`envs/<env>/backend/` esistente: ogni operazione ha una voce in `routes` verso un handler che esiste in `services/`
(e uguale a `x-kybes-handler`, se c'è), ogni function/microservizio ha la sua voce in `handlers`, ogni job in `jobs`;
voci di `routes` senza operazione e di `handlers` senza cartella in `services/` sono residui da rigenerare. Senza stack
backend non c'è niente da confrontare. Schema, manifest o tfvars illeggibili (anche non UTF-8) producono un finding o
un valore non dedotto, mai un'eccezione (fail closed).
"""
from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import mini_yaml
from rules import DEFAULT_RULES, Finding

RULE = "api-coverage"
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_VERSION = re.compile(r"v[0-9]+$")

MESSAGES = {
    "no-route": "operazione {route} senza handler nella mappatura generata ({tfvars}): aggiungi "
                "`x-kybes-handler: <contesto>/functions/<nome>` all'operazione (o conferma l'handler) e rigenera "
                "con /kynfra:create-backend-infra-aws",
    "missing-handler": "operazione {route} mappata su '{handler}', che non esiste in services/ (attesi "
                       "services/<contesto>/functions/<nome> o services/<contesto>/ms/<nome>)",
    "handler-no-infra": "{kind} '{handler}' senza infrastruttura in {stack}: rigenera con "
                        "/kynfra:create-backend-infra-aws",
    "job-no-infra": "job '{job}' senza infrastruttura (coda o schedule) in {stack}: rigenera con "
                    "/kynfra:create-backend-infra-aws",
    "route-mismatch": "operazione {route} mappata su '{target}' ma x-kybes-handler indica '{ref}': rigenera con "
                      "/kynfra:create-backend-infra-aws",
    "stale-route": "route '{route}' senza operazione in {openapi}: residuo, rigenera con "
                   "/kynfra:create-backend-infra-aws",
    "stale-handler": "handler '{handler}' in handlers senza cartella in services/: residuo, rigenera con "
                     "/kynfra:create-backend-infra-aws",
    "openapi": "schema OpenAPI non leggibile ({error}): api-coverage non può verificare la copertura",
    "tfvars-missing": "{file} mancante nello stack backend: rigenera con /kynfra:create-backend-infra-aws",
    "tfvars-unreadable": "{file} non leggibile ({error}): file generato, rigeneralo con "
                         "/kynfra:create-backend-infra-aws",
    "tfvars-bad": "{file} non leggibile: '{name}' deve essere un oggetto letterale (file generato, non modificarlo "
                  "a mano)",
}


class KybesError(ValueError):
    pass


@dataclass
class Handler:
    kind: str  # "function" | "ms"
    context: str
    name: str
    path: str  # cartella dell'handler
    runtime: Optional[str]
    handler: Optional[str]

    @property
    def key(self) -> str:
        return f"{self.context}/{'functions' if self.kind == 'function' else 'ms'}/{self.name}"


@dataclass
class Operation:
    method: str
    path: str
    operation_id: Optional[str]
    handler_ref: Optional[str]
    public: bool  # security: []
    line: int = 0  # riga dell'operazione nello schema (0 se non nota, es. JSON)

    @property
    def route(self) -> str:
        return f"{self.method} {self.path}"


@dataclass
class KybesProject:
    operations: List[Operation]
    handlers: Dict[str, Handler]  # chiave "<contesto>/functions/<nome>" | "<contesto>/ms/<nome>"
    jobs: List[str]
    has_db: bool


# ---------------------------------------------------------------- lettura

def _subdirs(d: Path) -> List[Path]:
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_dir() and not p.name.startswith("."))


def _operations(doc, lines) -> List[Operation]:
    if not isinstance(doc, dict):
        raise KybesError("il documento non è una mappa")
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        raise KybesError("'paths' non è una mappa")
    out: List[Operation] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for unsupported in ("$ref", "x-amazon-apigateway-any-method"):
            if unsupported in item:
                raise KybesError(f"{path}: '{unsupported}' nel path item non supportato (le operazioni vanno "
                                 "scritte una per metodo nello schema)")
        for method in METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            ref = None
            if "x-kybes-handler" in op:
                raw = op["x-kybes-handler"]
                if not isinstance(raw, str) or not raw.strip().strip("/"):
                    raise KybesError(f"{method.upper()} {path}: x-kybes-handler deve essere "
                                     "'<contesto>/functions/<nome>' o '<contesto>/ms/<nome>'")
                ref = raw.strip().strip("/")
            oid = op.get("operationId")
            out.append(Operation(method.upper(), str(path), oid if isinstance(oid, str) else None, ref,
                                 op.get("security") == [], lines.get(("paths", path, method), 0)))
    return out


def read_openapi(path: Path) -> List[Operation]:
    """Operazioni dello schema OpenAPI; KybesError se il file manca o non è nel sottoinsieme letto."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise KybesError(f"{path.name}: non è testo UTF-8") from None
    except OSError as e:
        raise KybesError(f"{path.name}: {e.strerror or e}") from None
    try:
        doc, lines = mini_yaml.load_with_lines(text)  # anche JSON, con le chiavi duplicate rifiutate
    except (ValueError, RecursionError) as e:
        raise KybesError(str(e)) from None
    return _operations(doc, lines)


def read_project(root: Path, openapi_rel: str = "schemas/openapi.yaml") -> KybesProject:
    """Progetto kybes in `root`. KybesError se lo schema OpenAPI manca o non è leggibile."""
    root = Path(root)
    handlers: Dict[str, Handler] = {}
    for ctx in _subdirs(root / "services"):
        for kind, sub in (("function", "functions"), ("ms", "ms")):
            for d in _subdirs(ctx / sub):
                h = Handler(kind, ctx.name, d.name, d.as_posix(), None, None)
                h.runtime, h.handler = runtime_of(h)
                handlers[h.key] = h
    db = root / "schemas" / "db"
    has_db = db.is_dir() and any(p.suffix.lower() in (".yaml", ".yml") for p in db.iterdir() if p.is_file())
    return KybesProject(read_openapi(root / openapi_rel), handlers, [d.name for d in _subdirs(root / "jobs")], has_db)


def runtime_of(h: Handler) -> Tuple[Optional[str], Optional[str]]:
    """(runtime Lambda, handler) dal manifest della cartella: package.json (`engines.node` → `nodejs<major>.x`,
    `main` → `<file senza estensione>.handler`), pyproject.toml (`requires-python` → `python3.<minor>`, handler
    `handler.handler` o `app.handler` secondo il file presente). None per ciò che non si deduce o non si legge.
    Con un intervallo (`>=20 <23`, `^3.11`) vale la prima versione scritta, cioè la più bassa ammessa."""
    d = Path(h.path)
    pkg = d / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        data = data if isinstance(data, dict) else {}
        engines = data.get("engines") if isinstance(data.get("engines"), dict) else {}
        m = re.search(r"[0-9]+", str(engines.get("node") or ""))
        runtime = f"nodejs{int(m.group(0))}.x" if m else None
        main = data.get("main")
        handler = None
        if isinstance(main, str) and main.strip():
            base = posixpath.normpath(main.strip().replace("\\", "/"))
            if base not in (".", "..") and not base.startswith(("../", "/")):
                handler = f"{posixpath.splitext(base)[0]}.handler"
        return runtime, handler
    runtime = None
    pyproject = d / "pyproject.toml"
    if pyproject.is_file():
        try:
            text = pyproject.read_text(encoding="utf-8")
        except (OSError, ValueError):
            text = ""
        m = re.search(r"""^\s*requires-python\s*=\s*["']([^"']*)["']""", text, re.M)
        v = re.search(r"3\.([0-9]+)", m.group(1)) if m else None
        runtime = f"python3.{int(v.group(1))}" if v else None
    for module in ("handler", "app"):
        if (d / f"{module}.py").is_file():
            return runtime, f"{module}.handler"
    return runtime, None


SCHEDULE_RE = re.compile(r"(cron|rate)\([^\"\\$%{}]+\)")


def job_schedule(root: Path, name: str) -> Optional[str]:
    """Espressione di schedule del job da `jobs/<nome>/job.yaml` (o `.yml`), chiave `schedule` (es.
    `cron(0 2 * * ? *)` o `rate(1 hour)`, sintassi di EventBridge Scheduler); None senza file o senza chiave (job su
    coda SQS). KybesError se il file non è leggibile o la chiave non è un'espressione valida."""
    for fname in ("job.yaml", "job.yml"):
        f = Path(root) / "jobs" / name / fname
        if not f.is_file():
            continue
        try:
            doc = mini_yaml.load(f.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            raise KybesError(f"jobs/{name}/{fname}: non è testo UTF-8") from None
        except (OSError, ValueError, RecursionError) as e:
            raise KybesError(f"jobs/{name}/{fname}: {e}") from None
        value = doc.get("schedule") if isinstance(doc, dict) else None
        if value is None:
            return None
        if not isinstance(value, str) or not SCHEDULE_RE.fullmatch(value.strip()):
            raise KybesError(f"jobs/{name}/{fname}: schedule deve essere 'cron(...)' o 'rate(...)' "
                             "(sintassi di EventBridge Scheduler)")
        return value.strip()
    return None


# ---------------------------------------------------------------- mappatura

def context_of(path: str) -> Optional[str]:
    """Contesto dalla convenzione `/v1/<contesto>/...` (prefisso di versione facoltativo)."""
    parts = [p for p in path.split("/") if p]
    if parts and _VERSION.match(parts[0]):
        parts = parts[1:]
    if not parts or "{" in parts[0]:
        return None
    return parts[0]


def resolve_mapping(p: KybesProject) -> Tuple[Dict[str, str], List[Operation]]:
    """("METODO percorso" -> chiave dell'handler, operazioni ambigue o non risolte)."""
    by_ctx: Dict[str, List[str]] = {}
    for key, h in p.handlers.items():
        by_ctx.setdefault(h.context, []).append(key)
    mapping: Dict[str, str] = {}
    unresolved: List[Operation] = []
    for op in p.operations:
        if op.handler_ref:
            mapping[op.route] = op.handler_ref
            continue
        candidates = by_ctx.get(context_of(op.path) or "", [])
        if len(candidates) == 1:
            mapping[op.route] = candidates[0]
        else:
            unresolved.append(op)
    return mapping, unresolved


# ---------------------------------------------------------------- copertura

def coverage_findings(p: KybesProject, mapping_tfvars: Dict[str, str], infra_handlers: Set[str],
                      infra_jobs: Set[str], openapi_path: str = "schemas/openapi.yaml",
                      handlers_path: str = "handlers.auto.tfvars",
                      jobs_path: str = "jobs.auto.tfvars") -> List[Finding]:
    """Finding `api-coverage` di uno stack backend: `mapping_tfvars` sono le `routes` di handlers.auto.tfvars,
    `infra_handlers` le chiavi di `handlers`, `infra_jobs` le chiavi di `jobs.auto.tfvars`. Le operazioni si
    ancorano alla loro riga dello schema, il resto al file tfvars."""
    sev = DEFAULT_RULES[RULE]
    stack = posixpath.dirname(handlers_path) or "."
    out: List[Finding] = []
    for op in p.operations:
        target = mapping_tfvars.get(op.route)
        if target is None:
            out.append(Finding(RULE, sev, openapi_path, op.line,
                               MESSAGES["no-route"].format(route=op.route, tfvars=handlers_path), op.route))
            continue
        for ref in dict.fromkeys(r for r in (target, op.handler_ref) if r):
            if ref not in p.handlers:
                out.append(Finding(RULE, sev, openapi_path, op.line,
                                   MESSAGES["missing-handler"].format(route=op.route, handler=ref), op.route))
        if op.handler_ref and target != op.handler_ref:
            out.append(Finding(RULE, sev, openapi_path, op.line, MESSAGES["route-mismatch"].format(
                route=op.route, target=target, ref=op.handler_ref), op.route))
    routes = {op.route for op in p.operations}
    for route in sorted(set(mapping_tfvars) - routes):
        out.append(Finding(RULE, sev, handlers_path, 0,
                           MESSAGES["stale-route"].format(route=route, openapi=openapi_path), route))
    for key in sorted(set(infra_handlers) - set(p.handlers)):
        out.append(Finding(RULE, sev, handlers_path, 0, MESSAGES["stale-handler"].format(handler=key), key))
    for key, h in sorted(p.handlers.items()):
        if key not in infra_handlers:
            kind = "function" if h.kind == "function" else "microservizio"
            out.append(Finding(RULE, sev, handlers_path, 0,
                               MESSAGES["handler-no-infra"].format(kind=kind, handler=key, stack=stack), key))
    for job in p.jobs:
        if job not in infra_jobs:
            out.append(Finding(RULE, sev, jobs_path, 0, MESSAGES["job-no-infra"].format(job=job, stack=stack), job))
    return out


def _tfvars_object(path: Path, name: str, rel: str) -> Tuple[Optional[dict], Optional[Finding]]:
    import hcl
    sev = DEFAULT_RULES[RULE]
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, Finding(RULE, sev, rel, 0, MESSAGES["tfvars-missing"].format(file=path.name))
    except UnicodeDecodeError:
        return None, Finding(RULE, sev, rel, 0, MESSAGES["tfvars-unreadable"].format(file=path.name,
                                                                                 error="non è testo UTF-8"))
    except OSError as e:
        return None, Finding(RULE, sev, rel, 0, MESSAGES["tfvars-unreadable"].format(file=path.name,
                                                                                 error=e.strerror or e))
    attr = hcl.parse_tfvars(text, path.name).get(name)
    value = attr.literal() if attr is not None else None
    if not isinstance(value, dict) or hcl.parse_problems(text, path.name):
        return None, Finding(RULE, sev, rel, attr.line if attr else 0,
                             MESSAGES["tfvars-bad"].format(file=path.name, name=name))
    return value, None


def project_findings(proj: Path, cfg: dict) -> List[Finding]:
    """`api-coverage` sull'intero progetto (percorsi relativi al progetto), per rules.check_project."""
    import rules
    conf = cfg.get("kybes")
    if not conf or cfg["rules"].get(RULE) == "off":
        return []
    conf = conf if isinstance(conf, dict) else {}
    root_rel = rules._normalize_infra_root(conf.get("root"))
    openapi = rules._normalize_infra_root(conf.get("openapi") or "schemas/openapi.yaml")
    if openapi == ".":
        openapi = "schemas/openapi.yaml"
    kroot = proj / root_rel
    openapi_rel = posixpath.normpath(posixpath.join(root_rel, openapi))
    if not (kroot / openapi).is_file():
        return []
    infra = cfg.get("infra_root", ".")
    envs = proj / infra / "envs"
    stacks = [d for d in _subdirs(envs) if (d / "backend").is_dir()]
    if not stacks:
        return []
    try:
        p = read_project(kroot, openapi)
    except KybesError as e:
        return [Finding(RULE, DEFAULT_RULES[RULE], openapi_rel, 0, MESSAGES["openapi"].format(error=e))]
    out: List[Finding] = []
    for env_dir in stacks:
        stack_rel = posixpath.normpath(posixpath.join(infra, "envs", env_dir.name, "backend"))
        h_rel, j_rel = f"{stack_rel}/handlers.auto.tfvars", f"{stack_rel}/jobs.auto.tfvars"
        handlers, bad_h = _tfvars_object(env_dir / "backend" / "handlers.auto.tfvars", "handlers", h_rel)
        routes, bad_r = (None, None) if bad_h else _tfvars_object(env_dir / "backend" / "handlers.auto.tfvars",
                                                                  "routes", h_rel)
        jobs: Optional[dict] = {}
        bad_j = None
        if p.jobs or (env_dir / "backend" / "jobs.auto.tfvars").is_file():
            jobs, bad_j = _tfvars_object(env_dir / "backend" / "jobs.auto.tfvars", "jobs", j_rel)
        out.extend(f for f in (bad_h, bad_r, bad_j) if f)
        if bad_h or bad_r:
            continue
        mapping = {k: v for k, v in routes.items() if isinstance(v, str)}
        out.extend(coverage_findings(p, mapping, set(handlers), set(jobs or {}) if not bad_j else set(p.jobs),
                                     openapi_rel, h_rel, j_rel))
    return out
