"""Regole AWS di kynfra (spec sez. 7.2, tabella AWS): una regola per famiglia, con il nome della spec.

Due tipi di regole:
- `AWS_RULES`, per file, con la firma di rules_common `(irel, blocks, text, cfg) -> List[Finding]`: valori degli
  attributi di una risorsa (ACL pubbliche, TLS, porte aperte, policy IAM, …). Girano in pre_write, nello stop gate e
  in CI (`rules.check_content`).
- `AWS_PROJECT_RULES`, d'insieme, con la firma `(files, cfg) -> List[Finding]` dove `files` = [(irel, blocchi)]: di
  default ricevono i file di una cartella Terraform (`modules/<p>/`, `envs/<env>/<stack>/`, `bootstrap/`) e
  correlano le risorse tra file (es. il bucket e la sua `aws_s3_bucket_public_access_block`, che deve referenziarlo:
  `bucket = aws_s3_bucket.<nome>.id`). Le regole con `scope = "project"` ricevono tutti i file del progetto (i toggle
  di prod, che legano i moduli ai tfvars degli stack di prod). Girano solo in `rules.check_project`, cioè nello stop
  gate e in CI: in pre_write un file si vede da solo e l'assenza di una risorsa compagna non è ancora un errore.

Regole "solo prod" (`is_prod`): nei file di `envs/prod/**` l'attributo si verifica direttamente; nei moduli il valore
di prod non si conosce, quindi l'attributo deve essere letterale conforme o dipendere da una variabile della tabella
`PROD_TOGGLES` (es. `web_acl_id = var.waf_enabled ? … : null`), e `prod_toggles` verifica che ogni stack di prod che
usa il modulo la attivi (argomento del modulo, `terraform.tfvars`/`*.auto.tfvars`, default della variabile).

Gli attributi di sicurezza si verificano sul letterale: un valore che dipende da un'espressione non verificabile
(variabile, funzione) è trattato come non conforme, salvo dove la spec prevede il valore per ambiente (toggle di prod,
retention, ARN). I riferimenti `local.<nome>` dello stesso file si risolvono; i `var.<nome>` di sg-open e
dell'endpoint EKS si risolvono nella regola d'insieme `var_values_project` (default della variabile o tfvars della
stessa cartella). Una variabile senza default né valore nella cartella resta non verificabile e non dà finding.
"""
from __future__ import annotations

import fnmatch
import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import hcl
import rules
from rules import DEFAULT_RULES, Finding, stack_of

MESSAGES = {
    # s3-private
    "s3-acl": "ACL pubblica ({acl}) sul bucket: togli l'ACL (aws_s3_bucket_ownership_controls con "
              "BucketOwnerEnforced) e servi i contenuti tramite CloudFront con OAC",
    "s3-acl-literal": "acl non letterale: scrivi \"private\" come letterale o togli l'ACL (BucketOwnerEnforced)",
    "s3-acl-grant": "grant ACL a AllUsers/AuthenticatedUsers: togli il grant, il bucket resta privato (accesso tramite "
                    "CloudFront con OAC o ruoli IAM)",
    "s3-pab-flags": "public access block incompleto ({flags}): imposta block_public_acls, block_public_policy, "
                    "ignore_public_acls e restrict_public_buckets = true (letterali)",
    "s3-versioning-status": "versioning non attivo: imposta versioning_configuration {{ status = \"Enabled\" }}",
    "s3-missing-pab": "bucket senza aws_s3_bucket_public_access_block nel modulo: aggiungilo con bucket = {ref}.id e "
                      "i 4 flag a true",
    "s3-missing-sse": "bucket senza cifratura: aggiungi aws_s3_bucket_server_side_encryption_configuration con "
                      "bucket = {ref}.id e sse_algorithm \"aws:kms\" (o \"AES256\")",
    "s3-missing-tls": "bucket senza policy TLS only: aggiungi aws_s3_bucket_policy con bucket = {ref}.id e uno "
                      "statement Deny su s3:* con condition Bool aws:SecureTransport = \"false\"",
    "s3-missing-versioning": "bucket senza versioning: aggiungi aws_s3_bucket_versioning con bucket = {ref}.id e "
                             "status = \"Enabled\"",
    # cloudfront-https
    "cf-viewer": "viewer_protocol_policy {value}: usa \"redirect-to-https\" (o \"https-only\") come letterale",
    "cf-tls": "TLS minimo {value}: imposta viewer_certificate {{ minimum_protocol_version = \"TLSv1.2_2021\" }} (o "
              "successivo) con un certificato ACM, non il certificato di default di CloudFront",
    "cf-oai": "origin S3 con OAI (s3_origin_config): usa origin_access_control_id = "
              "aws_cloudfront_origin_access_control.<nome>.id",
    "cf-website": "origin verso l'endpoint website pubblico del bucket: usa bucket_regional_domain_name con "
                  "origin_access_control_id (bucket privato)",
    "cf-oac": "origin S3 senza origin_access_control_id: aggiungi origin_access_control_id = "
              "aws_cloudfront_origin_access_control.<nome>.id",
    "cf-headers": "default_cache_behavior senza response_headers_policy_id: aggiungi una "
                  "aws_cloudfront_response_headers_policy (HSTS, CSP, X-Content-Type-Options, frame-ancestors) e "
                  "referenziala",
    "cf-logging": "distribuzione senza log di accesso: aggiungi logging_config {{ bucket = … }} o i log v2 "
                  "(aws_cloudwatch_log_delivery_source con resource_arn = {ref}.arn e aws_cloudwatch_log_delivery)",
    # lb-https
    "lb-http": "listener HTTP senza redirect: imposta default_action {{ type = \"redirect\" redirect {{ protocol = "
               "\"HTTPS\" port = \"443\" status_code = \"HTTP_301\" }} }}",
    "lb-rule-http": "regola su un listener HTTP che non fa redirect a HTTPS: su HTTP si fa solo redirect, sposta la "
                    "regola sul listener HTTPS",
    "lb-protocol": "protocol del listener non letterale: scrivi \"HTTPS\"/\"TLS\" (o \"HTTP\" con solo redirect) come "
                   "letterale",
    "lb-ssl": "ssl_policy {value} non moderna: usa \"ELBSecurityPolicy-TLS13-1-2-2021-06\" (o successiva della "
              "famiglia TLS13) come letterale",
    "lb-drop-headers": "drop_invalid_header_fields non attivo: imposta drop_invalid_header_fields = true",
    "lb-logs": "access_logs assenti o disattivi: aggiungi access_logs {{ bucket = … enabled = true }}",
    # sg-open
    "sg-sensitive": "ingress da {cidr} su porte di amministrazione o database ({ports}): apri solo da security group "
                    "sorgenti (referenced_security_group_id/security_groups), prefix list o CIDR interni; per "
                    "l'accesso amministrativo usa SSM Session Manager",
    "sg-port": "ingress da {cidr} su porte diverse da 80/443 ({ports}): dal mondo apri solo 80 e 443 (porte "
               "letterali), il resto da security group sorgenti o CIDR interni",
    "sg-dynamic": "dynamic \"ingress\" con for_each non verificabile e CIDR presi dall'iteratore: scrivi le regole "
                  "in un local con valori letterali (for_each = local.<nome>) o come blocchi/risorse espliciti, così "
                  "i guardrail vedono CIDR e porte",
    # iam-least-privilege
    "iam-wildcard": "statement Allow con Action \"*\" (o NotAction) su Resource \"*\": elenca le azioni e gli ARN "
                    "delle risorse necessarie",
    "iam-passrole": "iam:PassRole su Resource \"*\": limita Resource agli ARN dei ruoli da passare (con "
                    "condition iam:PassedToService)",
    "iam-principal": "Principal \"*\" in uno statement Allow senza condition che limiti chi accede: indica il "
                     "principal esatto (account, ruolo, servizio) o aggiungi una condition su aws:SourceArn, "
                     "aws:SourceAccount, aws:PrincipalOrgID…",
    "iam-admin": "policy gestita {name} troppo ampia: crea una policy con le sole azioni necessarie e collegala al "
                 "ruolo",
    "iam-unverifiable": "documento di policy non verificabile ({why}): scrivilo con jsonencode({{…}}) o data "
                        "\"aws_iam_policy_document\"",
    # kms-rotation, logs-retention
    "kms-rotation": "chiave KMS senza rotazione: imposta enable_key_rotation = true",
    "logs-retention": "log group senza retention: imposta retention_in_days (es. 30, 90, 365; non 0)",
    # eks-hardening
    "eks-public": "endpoint API pubblico senza CIDR espliciti: imposta endpoint_public_access = false (endpoint "
                  "privato) o public_access_cidrs con CIDR espliciti diversi da 0.0.0.0/0",
    "eks-secrets": "cluster senza cifratura dei Secret: aggiungi encryption_config {{ resources = [\"secrets\"] "
                   "provider {{ key_arn = aws_kms_key.<nome>.arn }} }}",
    "eks-logs": "log del control plane incompleti: imposta enabled_cluster_log_types = [\"api\", \"audit\", "
                "\"authenticator\", \"controllerManager\", \"scheduler\"]",
    "eks-imds": "launch template senza IMDSv2 obbligatorio: imposta metadata_options {{ http_tokens = \"required\" }}",
    "eks-nodegroup-lt": "node group senza launch template: aggiungi launch_template {{ id = "
                        "aws_launch_template.<nome>.id version = … }} con metadata_options {{ http_tokens = "
                        "\"required\" }}",
    # ecr-hardening
    "ecr-mutable": "tag mutabili: imposta image_tag_mutability = \"IMMUTABLE\"",
    "ecr-scan": "scansione al push disattiva: imposta image_scanning_configuration {{ scan_on_push = true }} o "
                "attiva l'enhanced scanning (aws_ecr_registry_scanning_configuration con scan_type = \"ENHANCED\")",
    "ecr-lifecycle": "repository senza lifecycle policy: aggiungi aws_ecr_lifecycle_policy con repository = "
                     "{ref}.name (scadenza delle immagini non taggate e delle vecchie)",
    # api-hardening
    "api-auth": "{route} senza authorizer: imposta un authorizer (JWT/COGNITO_USER_POOLS, CUSTOM o AWS_IAM); se la "
                "route è davvero pubblica, l'utente la aggiunge a public_routes in .kynfra/config.json",
    "api-logs": "stage senza access log: aggiungi access_log_settings {{ destination_arn = "
                "aws_cloudwatch_log_group.<nome>.arn format = jsonencode({{…}}) }} (JSON con correlationId)",
    "api-throttle": "stage senza throttling: aggiungi aws_api_gateway_method_settings con stage_name = "
                    "{ref}.stage_name, method_path = \"*/*\" e settings {{ throttling_rate_limit "
                    "throttling_burst_limit }} (o una usage plan con throttle_settings)",
    "api-throttle-v2": "stage senza throttling: aggiungi default_route_settings {{ throttling_rate_limit = … "
                       "throttling_burst_limit = … }}",
    # lambda-hardening
    "lambda-env": "variabile d'ambiente {name} con valore letterale: salva il valore in Secrets Manager e passa "
                  "l'ARN del segreto (es. DB_SECRET_ARN = aws_secretsmanager_secret.<nome>.arn)",
    "lambda-tracing": "funzione senza tracing X-Ray: aggiungi tracing_config {{ mode = \"Active\" }}",
    "lambda-logs": "funzione senza log group con retention: aggiungi aws_cloudwatch_log_group con name = "
                   "\"/aws/lambda/${{…function_name}}\" e retention_in_days (o logging_config {{ log_group = … }})",
    # toggle di prod
    "prod-stack": "{what} assente in prod: imposta {stack_fix}",
    "prod-module": "{what} non attivabile in prod: nel modulo scrivi {module_fix} (variabili ammesse: {vars}) e "
                   "attivala nei tfvars degli stack di prod",
    "prod-tfvars": "{what} non attivo in prod (stack {stack}): imposta {var} = {value} in terraform.tfvars "
                   "(e passalo al modulo che lo usa)",
    "prod-arg": "{what} disattivato in prod: il modulo riceve {var} = {raw}; passa {var} = var.{var} e imposta "
                "{var} = {value} in terraform.tfvars",
}


@dataclass(frozen=True)
class ProdToggle:
    rule: str
    types: Tuple[str, ...]
    attr: str
    variables: Tuple[str, ...]  # variabili ammesse nei moduli per attivarlo in prod
    what: str
    stack_fix: str
    module_fix: str


# Unica tabella dei toggle "solo prod": nomi delle variabili ammesse nei moduli e testi dei messaggi.
PROD_TOGGLES: Tuple[ProdToggle, ...] = (
    ProdToggle("cloudfront-https", ("aws_cloudfront_distribution",), "web_acl_id",
               ("waf_enabled", "web_acl_arn", "web_acl_id"), "WAF",
               "web_acl_id = aws_wafv2_web_acl.<nome>.arn (WAF con managed rule set)",
               "web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.<nome>[0].arn : null"),
    ProdToggle("lb-https", ("aws_lb", "aws_alb"), "enable_deletion_protection",
               ("deletion_protection", "enable_deletion_protection"), "deletion protection",
               "enable_deletion_protection = true",
               "enable_deletion_protection = var.deletion_protection"),
    ProdToggle("logs-retention", ("aws_cloudwatch_log_group",), "kms_key_id",
               ("kms_key_arn", "kms_key_id", "logs_kms_key_arn"), "cifratura KMS del log group",
               "kms_key_id = aws_kms_key.<nome>.arn",
               "kms_key_id = var.kms_key_arn"),
)

WORLD = ("0.0.0.0/0", "::/0")
SENSITIVE_PORTS = (22, 3389, 3306, 5432, 1433, 6379, 27017)
WEB_PORTS = (80, 443)
ICMP = ("icmp", "icmpv6", "1", "58")
PUBLIC_ACLS = ("public-read", "public-read-write", "authenticated-read")
PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
CF_TLS_OK = re.compile(r"TLSv1\.2_20(2[1-9]|[3-9]\d)|TLSv1\.3(_\d{4})?")
LB_SSL_PREFIXES = ("ELBSecurityPolicy-TLS13-1-2-", "ELBSecurityPolicy-TLS13-1-3-")
EKS_LOG_TYPES = ("api", "audit", "authenticator")
LAMBDA_SENSITIVE = ("PASSWORD", "SECRET", "TOKEN")
ADMIN_RE = re.compile(r"(?<![\w-])(AdministratorAccess|PowerUserAccess)(?![\w-])")
POLICY_ATTRS = {"policy", "assume_role_policy", "inline_policy"}
FILE_FUNC = re.compile(r"^(file|templatefile)\s*\(")
# condition che limitano chi può usare uno statement con Principal "*"
RESTRICTING_CONDITION_KEYS = {
    "aws:principalorgid", "aws:principalorgpaths", "aws:principalaccount", "aws:principalarn", "aws:sourceaccount",
    "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip",
    "aws:vpcsourceip", "aws:userid", "kms:calleraccount", "kms:viaservice", "sts:externalid",
    "s3:dataaccesspointaccount",
}

# riferimento risolvibile: `local.<nome>` (stesso file) o `var.<nome>` (default/tfvars della stessa cartella)
REF_FULL = re.compile(r"(local|var)\.[A-Za-z_][\w-]*")
# riferimento a una risorsa, data source o modulo (es. aws_wafv2_web_acl.w[0].arn)
RESOURCE_REF = re.compile(r"(?<![\w.])(data\.[A-Za-z_][\w-]*|aws_[\w-]+|module)\.[A-Za-z_][\w-]*(\[[^\]]*\])?\.\w")
VAR_RE = re.compile(r"\bvar\.([A-Za-z_][\w-]*)")
FOR_RE = re.compile(r"^[\[{]\s*for\s")
TFVARS_EXT = (".tfvars", ".tfvars.json")


def _f(rule: str, irel: str, line: int, key: str, resource: str = "", **fmt) -> Finding:
    return Finding(rule, DEFAULT_RULES.get(rule, "block"), irel, line, MESSAGES[key].format(**fmt), resource)


def is_prod(irel: str, cfg: dict) -> bool:
    """True per i file degli stack di prod (envs/prod/<stack>/…). Nei moduli il valore di prod non è determinabile:
    le regole "solo prod" lì si verificano sui tfvars degli stack di prod (`prod_toggles`)."""
    st = stack_of(irel)
    return st is not None and st[0] == "prod"


# ---------------------------------------------------------------- utilità sui blocchi

def _resources(blocks: Iterable[hcl.Block], *types: str) -> List[hcl.Block]:
    return [b for b in blocks if b.type == "resource" and b.labels[:1] and b.labels[0] in types]


def _walk(blocks: Iterable[hcl.Block]) -> Iterable[hcl.Block]:
    for b in blocks:
        yield b
        yield from _walk(b.blocks)


def _locals(blocks: Iterable[hcl.Block]) -> Dict[str, hcl.Attr]:
    """Ambiente di risoluzione del file: {"local.<nome>": valore}."""
    out: Dict[str, hcl.Attr] = {}
    for b in blocks:
        if b.type == "locals":
            out.update((f"local.{k}", a) for k, a in b.attrs.items())
    return out


def _resolve(attr: Optional[hcl.Attr], locs: Dict[str, hcl.Attr]) -> Optional[hcl.Attr]:
    """Segue `local.<nome>`/`var.<nome>` presenti nell'ambiente (fino a 5 livelli)."""
    for _ in range(5):
        if attr is None:
            return None
        raw = attr.raw.strip()
        if not REF_FULL.fullmatch(raw) or raw not in locs:
            return attr
        attr = locs[raw]
    return attr


def _lit(block: hcl.Block, name: str, locs: Optional[Dict[str, hcl.Attr]] = None):
    a = _resolve(block.get(name), locs or {})
    return a.literal() if a is not None else None


def _is_true(block: hcl.Block, name: str, locs: Optional[Dict[str, hcl.Attr]] = None) -> bool:
    return _lit(block, name, locs) is True


def _truth(attr: hcl.Attr) -> Optional[bool]:
    """Valore di verità di un letterale (null, false, "", 0, [] → False); None se non è un letterale."""
    raw = attr.raw.strip()
    if raw == "null":
        return False
    v = attr.literal()
    if v is None:
        return None
    if isinstance(v, str) and v.strip().lower() in ("", "false", "0"):
        return False
    return bool(v)


def _ref(block: hcl.Block) -> str:
    return block.address()


def _refers(raw: str, rtype: str, name: str, attrs: Tuple[str, ...]) -> bool:
    """`raw` è un riferimento a `<rtype>.<name>[indice].<attr>` (con uno degli attributi indicati)."""
    pat = rf"{re.escape(rtype)}\.{re.escape(name)}(\[[^\]]*\])?\.({'|'.join(attrs)})"
    return re.fullmatch(pat, raw.strip()) is not None


def _mentions(raw: str, rtype: str, name: str) -> bool:
    return re.search(rf"(?<![\w.]){re.escape(rtype)}\.{re.escape(name)}(?![\w-])", raw) is not None


# ---------------------------------------------------------------- valori HCL parziali (per le policy IAM)

class Expr(str):
    """Espressione non letterale (testo grezzo)."""


class _Obj(dict):
    line = 0


def _scan_to(s: str, i: int, close: str) -> List[Tuple[int, int]]:
    """Da dopo una parentesi aperta: intervalli degli elementi separati da virgole a profondità 0, fino a `close`.
    Solleva ValueError se la parentesi non si chiude."""
    parts: List[Tuple[int, int]] = []
    start, depth, n = i, 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            i = hcl._skip_string(s, i)
            continue
        if c == "<":
            k = hcl._skip_heredoc(s, i)
            if k is not None:
                i = k
                continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                if c != close:
                    raise ValueError(c)
                parts.append((start, i))
                return parts
            depth -= 1
        elif c == "," and depth == 0:
            parts.append((start, i))
            start = i + 1
        i += 1
    raise ValueError("non chiusa")


def _value(raw: str, line: int, locs: Dict[str, hcl.Attr], depth: int = 0):
    """Valore Python di un'espressione HCL anche parzialmente non letterale: oggetti → _Obj (con la riga), liste →
    list, letterali → valore, il resto → Expr."""
    raw = raw.strip()
    if depth > 20:
        return Expr(raw)
    if REF_FULL.fullmatch(raw) and raw in locs:
        a = locs[raw]
        return _value(a.raw, a.line, locs, depth + 1)
    attr = hcl.Attr("", line, raw)
    if raw.startswith("{") and not FOR_RE.match(raw):
        entries = attr.entries()
        if entries is not None:
            obj = _Obj((k, _value(v.raw, v.line, locs, depth + 1)) for k, v in entries.items())
            obj.line = line
            return obj
    if raw.startswith("[") and raw.endswith("]") and not FOR_RE.match(raw):
        try:
            spans = _scan_to(raw, 1, "]")
        except ValueError:
            spans = None
        if spans is not None and spans[-1][1] == len(raw) - 1:
            out = []
            for a, b in spans:
                item = raw[a:b]
                if not item.strip():
                    continue
                lead = len(item) - len(item.lstrip())
                out.append(_value(item, line + raw.count("\n", 0, a + lead), locs, depth + 1))
            return out
    if raw == "null":
        return None
    v = attr.literal()
    return Expr(raw) if v is None else v


def _jsonencode_arg(raw: str) -> Optional[str]:
    m = re.match(r"jsonencode\s*\(", raw.strip())
    if not m:
        return None
    s = raw.strip()
    try:
        spans = _scan_to(s, m.end(), ")")
    except ValueError:
        return None
    if len(spans) != 1 or spans[0][1] != len(s) - 1:
        return None
    return s[spans[0][0]:spans[0][1]]


def _heredoc_body(raw: str) -> Optional[str]:
    m = re.match(r"<<(-?)([A-Za-z_][\w-]*)[ \t]*\r?\n(.*)\n[ \t]*\2[ \t]*$", raw.strip(), re.S)
    return m.group(3) if m else None


def _json_with_exprs(text: str) -> Optional[object]:
    """JSON con interpolazioni `${…}`: dentro le stringhe diventano __EXPR__, fuori "__EXPR__"."""
    if "%{" in text:
        return None
    out: List[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str and c == "\\":
            out.append(text[i:i + 2])
            i += 2
            continue
        if c == '"':
            in_str = not in_str
        if text.startswith("$${", i):
            out.append("${")
            i += 3
            continue
        if text.startswith("${", i):
            j = hcl._skip_interp(text, i + 2)
            out.append("__EXPR__" if in_str else '"__EXPR__"')
            i = j
            continue
        out.append(c)
        i += 1
    try:
        return json.loads("".join(out))
    except ValueError:
        return None


# ---------------------------------------------------------------- statement IAM

@dataclass
class Stmt:
    line: int
    effect: object = "Allow"
    actions: list = field(default_factory=list)
    not_actions: bool = False
    resources: list = field(default_factory=list)
    not_resources: bool = False
    principals: list = field(default_factory=list)
    conditions: Optional[List[Tuple[str, str, list]]] = None  # (test, chiave, valori); None = nessuna condition


def _as_list(v) -> list:
    if v is None:
        return []
    return list(v) if isinstance(v, list) else [v]


def _principal_ids(p) -> list:
    if isinstance(p, dict):
        return [x for v in p.values() for x in _as_list(v)]
    return _as_list(p)


def _json_conditions(c) -> Optional[List[Tuple[str, str, list]]]:
    if c is None:
        return None
    if not isinstance(c, dict):
        return [("?", "?", [])]
    out: List[Tuple[str, str, list]] = []
    for test, body in c.items():
        if isinstance(body, dict):
            out.extend((str(test), str(k), _as_list(v)) for k, v in body.items())
        else:
            out.append((str(test), "?", []))
    return out


def _doc_statements(doc, line: int) -> List[Stmt]:
    """Statement di un documento di policy (dict da JSON o da jsonencode)."""
    if not isinstance(doc, dict):
        return []
    sts = doc.get("Statement")
    out: List[Stmt] = []
    for s in _as_list(sts):
        if not isinstance(s, dict):
            continue
        out.append(Stmt(
            line=getattr(s, "line", 0) or line,
            effect=s.get("Effect", "Allow"),
            actions=_as_list(s.get("Action")),
            not_actions="NotAction" in s,
            resources=_as_list(s.get("Resource")),
            not_resources="NotResource" in s,
            principals=_principal_ids(s.get("Principal")),
            conditions=_json_conditions(s.get("Condition")),
        ))
    return out


def _data_doc_statements(block: hcl.Block, locs: Dict[str, hcl.Attr], docs: Dict[str, hcl.Block],
                         seen: Optional[set] = None) -> List[Stmt]:
    """Statement di un data "aws_iam_policy_document", inclusi i documenti in source/override_policy_documents."""
    seen = seen if seen is not None else set()
    seen.add(id(block))

    def val(b: hcl.Block, name: str):
        a = b.get(name)
        return _value(a.raw, a.line, locs) if a is not None else None

    stmts: List[hcl.Block] = list(block.children("statement"))
    for dyn in block.children("dynamic"):
        if dyn.labels[:1] == ["statement"]:
            stmts.extend(dyn.children("content"))
    out: List[Stmt] = []
    for st in stmts:
        principals: list = []
        for p in st.children("principals"):
            principals.extend(_as_list(val(p, "identifiers")))
            if p.get("type") is not None and p.get("type").literal() == "*":
                principals.append("*")
        conds = [(str(_lit(c, "test") or "?"), str(_lit(c, "variable") or "?"), _as_list(val(c, "values")))
                 for c in st.children("condition")]
        eff = val(st, "effect")
        out.append(Stmt(
            line=st.line,
            effect="Allow" if st.get("effect") is None else eff,
            actions=_as_list(val(st, "actions")),
            not_actions=st.get("not_actions") is not None,
            resources=_as_list(val(st, "resources")),
            not_resources=st.get("not_resources") is not None,
            principals=principals,
            conditions=conds or None,
        ))
    for name in ("source_policy_documents", "override_policy_documents"):
        for item in _as_list(val(block, name)):
            other = _doc_ref(item, docs)
            if other is not None and id(other) not in seen:
                out.extend(_data_doc_statements(other, locs, docs, seen))
    return out


def _doc_ref(raw, docs: Dict[str, hcl.Block]) -> Optional[hcl.Block]:
    m = re.fullmatch(r"data\.aws_iam_policy_document\.([\w-]+)(\[[^\]]*\])?\.(json|minified_json)", str(raw).strip())
    return docs.get(m.group(1)) if m else None


def _json_expr(attr: hcl.Attr) -> str:
    """Espressione di un attributo; in .tf.json una stringa che è un'unica interpolazione `"${…}"` vale come
    l'espressione interna."""
    v = attr.json_value
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("${") and hcl._skip_interp(s, 2) == len(s):
            return s[2:-1].strip()
    return attr.raw.strip()


def _policy_statements(attr: hcl.Attr, locs: Dict[str, hcl.Attr],
                       docs: Optional[Dict[str, hcl.Block]] = None) -> Tuple[Optional[List[Stmt]], str]:
    """(statement, motivo) di un attributo che contiene un documento di policy.

    (None, "") se l'attributo non è un documento di policy; (None, motivo) se lo è ma non si può leggere."""
    raw = _json_expr(attr)
    inner = _jsonencode_arg(raw)
    if inner is not None:
        doc = _value(inner, attr.line, locs)
        if isinstance(doc, dict) and "Statement" in doc:
            return _doc_statements(doc, attr.line), ""
        return None, ""
    if docs is not None:
        other = _doc_ref(raw, docs)
        if other is not None:
            return _data_doc_statements(other, locs, docs), ""
    if raw.startswith("<<"):
        text = attr.literal()
        if not isinstance(text, str):
            text = _heredoc_body(raw)
    elif raw.startswith('"'):
        text = attr.literal()
    else:
        return None, ""
    if not isinstance(text, str) or not text.lstrip().startswith("{") or "Statement" not in text:
        return None, ""
    try:
        doc = json.loads(text)
    except ValueError:
        doc = _json_with_exprs(text)
    if not isinstance(doc, dict):
        return None, "JSON non leggibile"
    return _doc_statements(doc, attr.line), ""


def _is_allow(effect) -> bool:
    return not (isinstance(effect, str) and not isinstance(effect, Expr) and effect.lower() == "deny")


def _strs(values: list) -> List[str]:
    return [v.lower() for v in values if isinstance(v, str) and not isinstance(v, Expr)]


def _statement_problem(s: Stmt) -> Optional[str]:
    if not _is_allow(s.effect):
        return None
    actions = _strs(s.actions)
    star_res = "*" in _strs(s.resources) or s.not_resources
    if star_res and ("*" in actions or "*:*" in actions or s.not_actions):
        return "iam-wildcard"
    if star_res and any(fnmatch.fnmatchcase("iam:passrole", a) for a in actions):
        return "iam-passrole"
    if "*" in _strs(s.principals):
        keys = [k.lower() for _, k, _ in (s.conditions or [])]
        if not any(k == "?" or k in RESTRICTING_CONDITION_KEYS for k in keys):
            return "iam-principal"
    return None


def _named_values(attr: hcl.Attr, depth: int = 0) -> Iterable[hcl.Attr]:
    yield attr
    if depth < 4 and attr.raw.lstrip().startswith("{"):
        for sub in (attr.entries() or {}).values():
            yield from _named_values(sub, depth + 1)


# ---------------------------------------------------------------- toggle di prod (parte per file)

def _toggles_for(rtype: str) -> List[ProdToggle]:
    return [t for t in PROD_TOGGLES if rtype in t.types]


REF_PATTERN = r"(?:data\.[A-Za-z_][\w-]*|aws_[\w-]+|module)\.[A-Za-z_][\w-]*(?:\[[^\]]*\])?(?:\.[\w-]+)+"


def _arn_toggle(t: ProdToggle) -> bool:
    """Toggle il cui attributo è un ARN/ID (web_acl_id, kms_key_id), non un booleano (enable_…)."""
    return not t.attr.startswith("enable_")


def _toggle_ok_in_module(raw: str, t: ProdToggle) -> bool:
    """Forme ammesse nel modulo (dopo la risoluzione dei locals): `var.<ammessa>`, `var.<ammessa> ? <rif> : null`,
    un riferimento a risorsa/data/modulo (anche con [0]/[*]); il letterale true lo valuta il chiamante. Ogni altra
    espressione (condizionali costanti, try(), &&, …) non è verificabile."""
    allowed = "|".join(re.escape(v) for v in t.variables)
    return bool(re.fullmatch(rf"var\.(?:{allowed})", raw)
                or re.fullmatch(rf"var\.(?:{allowed})\s*\?\s*{REF_PATTERN}\s*:\s*null", raw)
                or _pure_ref(raw))


def _prod_toggle_findings(irel: str, block: hcl.Block, cfg: dict, locs: Dict[str, hcl.Attr]) -> List[Finding]:
    """Toggle "solo prod" nei file: nei moduli l'attributo deve esserci e dipendere da una risorsa o da una variabile
    ammessa (PROD_TOGGLES); negli stack di prod deve essere un letterale vero, una var.<nome> (verificata nei tfvars
    da `prod_toggles`) o, per i toggle ARN, un riferimento a una risorsa. Ogni altra espressione è non verificabile
    → finding."""
    out: List[Finding] = []
    in_module = irel.startswith("modules/")
    if not (in_module or is_prod(irel, cfg)):
        return out
    for t in _toggles_for(block.labels[0]):
        a = block.get(t.attr)
        r = _resolve(a, locs)
        line = a.line if a is not None else block.line
        if r is None:
            ok = False
        else:
            truth = _truth(r)
            raw = r.raw.strip()
            if truth is not None:
                ok = truth
            elif in_module:
                ok = _toggle_ok_in_module(raw, t)
            else:
                ok = bool(re.fullmatch(r"var\.[A-Za-z_][\w-]*", raw) or (_arn_toggle(t) and _pure_ref(raw)))
        if not ok:
            key = "prod-module" if in_module else "prod-stack"
            out.append(_f(t.rule, irel, line, key, _ref(block), what=t.what, stack_fix=t.stack_fix,
                          module_fix=t.module_fix, vars=", ".join(t.variables)))
    return out


def _pure_ref(raw: str) -> bool:
    """`raw` è solo un riferimento a una risorsa/data/modulo (es. aws_wafv2_web_acl.w.arn), senza logica."""
    return re.fullmatch(REF_PATTERN, raw) is not None


# ---------------------------------------------------------------- regole per file

def s3_private(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for b in _resources(blocks, "aws_s3_bucket", "aws_s3_bucket_acl"):
        acl = b.get("acl")
        if acl is not None:
            v = _resolve(acl, locs).literal()
            if not isinstance(v, str):
                out.append(_f("s3-private", irel, acl.line, "s3-acl-literal", _ref(b)))
            elif v in PUBLIC_ACLS:
                out.append(_f("s3-private", irel, acl.line, "s3-acl", _ref(b), acl=v))
        # grantee di access_control_policy (aws_s3_bucket_acl) e grant legacy di aws_s3_bucket
        for g in (x for x in _walk(b.blocks) if x.type in ("grantee", "grant")):
            uri = g.get("uri")
            if uri is not None and re.search(r"AllUsers|AuthenticatedUsers", uri.raw):
                out.append(_f("s3-private", irel, g.line, "s3-acl-grant", _ref(b)))
    for b in _resources(blocks, "aws_s3_bucket_public_access_block"):
        bad = [k for k in PAB_FLAGS if not _is_true(b, k, locs)]
        if bad:
            # riga del primo flag sbagliato; quella del blocco se un flag manca
            line = b.line if any(b.get(k) is None for k in bad) else min(b.get(k).line for k in bad)
            out.append(_f("s3-private", irel, line, "s3-pab-flags", _ref(b), flags=", ".join(bad)))
    for b in _resources(blocks, "aws_s3_bucket_versioning"):
        vc = b.children("versioning_configuration")
        if not vc or _lit(vc[0], "status", locs) != "Enabled":
            st = vc[0].get("status") if vc else None
            out.append(_f("s3-private", irel, st.line if st else b.line, "s3-versioning-status", _ref(b)))
    return out


def cloudfront_https(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for d in _resources(blocks, "aws_cloudfront_distribution"):
        res = _ref(d)
        behaviors = d.children("default_cache_behavior") + d.children("ordered_cache_behavior")
        for cb in behaviors:
            vpp = cb.get("viewer_protocol_policy")
            v = _lit(cb, "viewer_protocol_policy", locs)
            if v not in ("redirect-to-https", "https-only"):
                out.append(_f("cloudfront-https", irel, vpp.line if vpp else cb.line, "cf-viewer", res,
                              value=f'"{v}"' if isinstance(v, str) else (vpp.raw if vpp else "assente")))
        for cb in d.children("default_cache_behavior"):
            if cb.get("response_headers_policy_id") is None:
                out.append(_f("cloudfront-https", irel, cb.line, "cf-headers", res))
        vc = d.children("viewer_certificate")
        mpv_attr = vc[0].get("minimum_protocol_version") if vc else None
        mpv = _lit(vc[0], "minimum_protocol_version", locs) if vc else None
        default_cert = bool(vc) and _is_true(vc[0], "cloudfront_default_certificate", locs)
        if not vc or default_cert or not (isinstance(mpv, str) and CF_TLS_OK.fullmatch(mpv)):
            line = mpv_attr.line if mpv_attr is not None and not default_cert else (vc[0].line if vc else d.line)
            value = "del certificato di default (TLSv1)" if default_cert or mpv_attr is None else mpv_attr.raw
            out.append(_f("cloudfront-https", irel, line, "cf-tls", res, value=value))
        for o in d.children("origin"):
            dom = o.get("domain_name")
            draw = dom.raw if dom is not None else ""
            if o.children("s3_origin_config"):
                out.append(_f("cloudfront-https", irel, o.children("s3_origin_config")[0].line, "cf-oai", res))
            elif re.search(r"website_(endpoint|domain)|s3-website", draw):
                out.append(_f("cloudfront-https", irel, dom.line, "cf-website", res))
            elif re.search(r"bucket_(regional_)?domain_name|\.s3[.-]", draw) and \
                    o.get("origin_access_control_id") is None:
                out.append(_f("cloudfront-https", irel, o.line, "cf-oac", res))
        out.extend(_prod_toggle_findings(irel, d, cfg, locs))
    return out


def _listener_protocol(lst: hcl.Block, locs) -> Optional[str]:
    a = lst.get("protocol")
    if a is None:
        return "HTTP"
    v = _resolve(a, locs).literal()
    return v.upper() if isinstance(v, str) else None


def _redirects_to_https(actions: List[hcl.Block], locs) -> bool:
    if not actions:
        return False
    for act in actions:
        red = act.children("redirect")
        if _lit(act, "type", locs) != "redirect" or not red:
            return False
        proto = _lit(red[0], "protocol", locs)
        if not (isinstance(proto, str) and proto.upper() == "HTTPS"):
            return False
    return True


def lb_https(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for lst in _resources(blocks, "aws_lb_listener", "aws_alb_listener"):
        res = _ref(lst)
        proto = _listener_protocol(lst, locs)
        if proto is None:
            out.append(_f("lb-https", irel, lst.get("protocol").line, "lb-protocol", res))
        elif proto == "HTTP":
            acts = lst.children("default_action")
            if not _redirects_to_https(acts, locs):
                out.append(_f("lb-https", irel, acts[0].line if acts else lst.line, "lb-http", res))
        elif proto in ("HTTPS", "TLS"):
            sp = lst.get("ssl_policy")
            v = _lit(lst, "ssl_policy", locs)
            if not (isinstance(v, str) and v.startswith(LB_SSL_PREFIXES)):
                out.append(_f("lb-https", irel, sp.line if sp else lst.line, "lb-ssl", res,
                              value=sp.raw if sp else "assente (default ELBSecurityPolicy-2016-08)"))
    for lb in _resources(blocks, "aws_lb", "aws_alb"):
        res = _ref(lb)
        kind = _lit(lb, "load_balancer_type", locs)
        if kind == "gateway":
            continue
        if kind not in ("network",):
            if not _is_true(lb, "drop_invalid_header_fields", locs):
                a = lb.get("drop_invalid_header_fields")
                out.append(_f("lb-https", irel, a.line if a else lb.line, "lb-drop-headers", res))
        logs = lb.children("access_logs")
        if not logs or not _is_true(logs[0], "enabled", locs) or logs[0].get("bucket") is None:
            out.append(_f("lb-https", irel, logs[0].line if logs else lb.line, "lb-logs", res))
        out.extend(_prod_toggle_findings(irel, lb, cfg, locs))
    return out


def _world_cidr(attrs: List[Optional[hcl.Attr]], locs) -> Optional[str]:
    for a in attrs:
        if a is None:
            continue
        r = _resolve(a, locs)
        v = _value(r.raw, r.line, locs)
        for item in _as_list(v):
            if isinstance(item, str) and not isinstance(item, Expr) and item.strip() in WORLD:
                return item.strip()
        for w in WORLD:
            if w in r.raw:
                return w
    return None


def _port(a: Optional[hcl.Attr], locs) -> Optional[int]:
    if a is None:
        return None
    v = _resolve(a, locs).literal()
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"-?\d+", v.strip()):
        return int(v)
    return None


def _sg_problem(b: hcl.Block, proto_attr: str, locs) -> Optional[Tuple[str, str]]:
    """(chiave del messaggio, porte) se la regola di ingress aperta al mondo non è ammessa."""
    pa = b.get(proto_attr)
    proto = _resolve(pa, locs).literal() if pa is not None else None
    proto = str(proto).lower() if proto is not None and not isinstance(proto, bool) else None
    if proto in ICMP:
        return None
    if proto in ("-1", "all"):
        return "sg-sensitive", "tutte le porte"
    lo, hi = _port(b.get("from_port"), locs), _port(b.get("to_port"), locs)
    if proto is None or lo is None or hi is None:
        return "sg-port", "porte o protocollo non letterali"
    if lo > hi:
        lo, hi = hi, lo
    hit = [p for p in SENSITIVE_PORTS if lo <= p <= hi]
    ports = str(lo) if lo == hi else f"{lo}-{hi}"
    if hit:
        return "sg-sensitive", ", ".join(map(str, hit)) + ("" if ports == str(hit[0]) else f" nel range {ports}")
    if lo == hi and lo in WEB_PORTS:
        return None
    return "sg-port", ports


def _plain(v) -> bool:
    """Valore interamente letterale (nessuna Expr dentro): si può riscrivere come letterale HCL."""
    if isinstance(v, Expr):
        return False
    if isinstance(v, dict):
        return all(_plain(x) for x in v.values())
    if isinstance(v, list):
        return all(_plain(x) for x in v)
    return v is not None


_IDENTITY_MAP = re.compile(r"\{\s*for\s+(\w+)\s*,\s*(\w+)\s+in\s+(.+?)\s*:\s*\1\s*=>\s*\2\s*\}", re.S)
_IDENTITY_LIST = re.compile(r"\[\s*for\s+(\w+)\s+in\s+(.+?)\s*:\s*\1\s*\]", re.S)


def _iter_items(fe: hcl.Attr, env: Dict[str, hcl.Attr]) -> Optional[List[Tuple[object, object]]]:
    """(chiave, valore) degli elementi del for_each risolto (locals/var, for-expression identità); None se non
    risolvibile."""
    r = _resolve(fe, env)
    raw = r.raw.strip()
    for _ in range(5):
        m = _IDENTITY_MAP.fullmatch(raw) or _IDENTITY_LIST.fullmatch(raw)
        if not m:
            break
        inner = hcl.Attr("", r.line, m.group(m.lastindex))
        r = _resolve(inner, env)
        raw = r.raw.strip()
    coll = _value(raw, r.line, env)
    if isinstance(coll, dict):
        return list(coll.items())
    if isinstance(coll, list):
        return [(v if isinstance(v, str) else i, v) for i, v in enumerate(coll)]
    return None


def _subst_iter(raw: str, it: str, key, item) -> str:
    """Sostituisce in `raw` ogni `<it>.value.<k>`, `<it>.value["k"]`, `lookup(<it>.value, "k", …)`, `<it>.value` e
    `<it>.key` con il letterale dell'elemento (se interamente letterale)."""
    e = re.escape(it)

    def lit(v, fallback: str) -> str:
        return json.dumps(v) if _plain(v) else fallback

    def field(k):
        return item.get(k) if isinstance(item, dict) else None

    raw = re.sub(rf"lookup\(\s*{e}\.value\s*,\s*\"([\w-]+)\"\s*(?:,\s*([^()]*?))?\s*\)",
                 lambda m: lit(field(m.group(1)), m.group(2) if m.group(2) and field(m.group(1)) is None
                               else m.group(0)), raw)
    raw = re.sub(rf"(?<![\w.]){e}\.value(?:\.([\w-]+)|\[\"([\w-]+)\"\])",
                 lambda m: lit(field(m.group(1) or m.group(2)), m.group(0)), raw)
    raw = re.sub(rf"(?<![\w.]){e}\.value(?![\w.\[])", lambda m: lit(item, m.group(0)), raw)
    raw = re.sub(rf"(?<![\w.]){e}\.key(?![\w.\[])", lambda m: lit(key, m.group(0)), raw)
    return raw


def _dynamic_rules(dyn: hcl.Block, env: Dict[str, hcl.Attr]) -> Tuple[List[hcl.Block], bool]:
    """Regole di un `dynamic "ingress"`: un blocco per elemento del for_each risolto, con i riferimenti
    all'iteratore sostituiti dai valori dell'elemento. Restituisce (blocchi, non_risolto): se il for_each non è
    risolvibile, il content così com'è e True."""
    contents = dyn.children("content")
    fe = dyn.get("for_each")
    if not contents or fe is None:
        return contents, False
    items = _iter_items(fe, env)
    if items is None:
        return contents, True
    it = _iterator(dyn)
    out: List[hcl.Block] = []
    for content in contents:
        for key, item in items:
            attrs = {name: hcl.Attr(name, a.line, _subst_iter(a.raw.strip(), it, key, item))
                     for name, a in content.attrs.items()}
            out.append(hcl.Block(content.type, [], content.line, content.end_line, attrs, []))
    return out, False


def _iterator(dyn: hcl.Block) -> str:
    it_attr = dyn.get("iterator")
    return it_attr.raw.strip() if it_attr is not None else (dyn.labels[0] if dyn.labels else "ingress")


def _sg_findings(irel: str, blocks: List[hcl.Block], env: Dict[str, hcl.Attr]) -> List[Finding]:
    out: List[Finding] = []
    seen = set()

    def check(rule_block: hcl.Block, cidr_attrs: Tuple[str, ...], proto_attr: str, line: int, res: str) -> None:
        cidr = _world_cidr([rule_block.get(a) for a in cidr_attrs], env)
        if cidr is None:
            return
        prob = _sg_problem(rule_block, proto_attr, env)
        if prob and (line, prob) not in seen:
            seen.add((line, prob))
            out.append(_f("sg-open", irel, line, prob[0], res, cidr=cidr, ports=prob[1]))

    for sg in _resources(blocks, "aws_security_group", "aws_default_security_group"):
        ingress = list(sg.children("ingress"))
        for dyn in sg.children("dynamic"):
            if dyn.labels[:1] != ["ingress"]:
                continue
            blocks_, unresolved = _dynamic_rules(dyn, env)
            it = re.escape(_iterator(dyn))
            # fail closed: CIDR che dipendono dall'iteratore di un for_each non risolvibile
            if unresolved and any(re.search(rf"(?<![\w.]){it}\.(value|key)", a.raw)
                                  for c in blocks_ for n, a in c.attrs.items()
                                  if n in ("cidr_blocks", "ipv6_cidr_blocks")):
                if (dyn.line, "dyn") not in seen:
                    seen.add((dyn.line, "dyn"))
                    out.append(_f("sg-open", irel, dyn.line, "sg-dynamic", _ref(sg)))
                continue
            ingress.extend(blocks_)
        for ing in ingress:
            check(ing, ("cidr_blocks", "ipv6_cidr_blocks"), "protocol", ing.line, _ref(sg))
    for r in _resources(blocks, "aws_security_group_rule"):
        if _lit(r, "type", env) != "egress":
            check(r, ("cidr_blocks", "ipv6_cidr_blocks"), "protocol", r.line, _ref(r))
    for r in _resources(blocks, "aws_vpc_security_group_ingress_rule"):
        check(r, ("cidr_ipv4", "cidr_ipv6"), "ip_protocol", r.line, _ref(r))
    return out


def sg_open(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    """Ingress aperti al mondo; `var.*` si risolvono nella regola d'insieme (`var_values_project`)."""
    return _sg_findings(irel, blocks, _locals(blocks))


def iam_least_privilege(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    seen = set()

    def add(line: int, key: str, res: str, **fmt) -> None:
        if (line, key) not in seen:
            seen.add((line, key))
            out.append(_f("iam-least-privilege", irel, line, key, res, **fmt))

    def check(stmts: List[Stmt], res: str) -> None:
        for s in stmts:
            prob = _statement_problem(s)
            if prob:
                add(s.line, prob, res)

    for top in blocks:
        res = "" if top.type in ("tfvars", "locals") else top.address()
        if top.type == "data" and top.labels[:1] == ["aws_iam_policy_document"]:
            check(_data_doc_statements(top, locs, {}), res)
        for b in _walk([top]):
            for attr in b.attrs.values():
                if attr.name != "description":
                    m = ADMIN_RE.search(attr.raw)
                    if m:
                        add(attr.line, "iam-admin", res, name=m.group(1))
                if attr.name in POLICY_ATTRS and FILE_FUNC.match(_json_expr(attr)):
                    add(attr.line, "iam-unverifiable", res, why="file esterno al codice Terraform")
                    continue
                for a in _named_values(attr):
                    stmts, why = _policy_statements(a, locs)
                    if why:
                        add(a.line, "iam-unverifiable", res, why=why)
                    elif stmts:
                        check(stmts, res)
    return out


def kms_rotation(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for k in _resources(blocks, "aws_kms_key"):
        spec = _lit(k, "customer_master_key_spec")
        if isinstance(spec, str) and spec != "SYMMETRIC_DEFAULT":
            continue  # le chiavi asimmetriche e HMAC non supportano la rotazione automatica
        if not _is_true(k, "enable_key_rotation"):
            a = k.get("enable_key_rotation")
            out.append(_f("kms-rotation", irel, a.line if a else k.line, "kms-rotation", _ref(k)))
    return out


def logs_retention(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for g in _resources(blocks, "aws_cloudwatch_log_group"):
        a = g.get("retention_in_days")
        if a is None or _truth(a) is False:
            out.append(_f("logs-retention", irel, a.line if a else g.line, "logs-retention", _ref(g)))
        out.extend(_prod_toggle_findings(irel, g, cfg, locs))
    return out


def _eks_public(irel: str, blocks: List[hcl.Block], env: Dict[str, hcl.Attr]) -> List[Finding]:
    out: List[Finding] = []
    for c in _resources(blocks, "aws_eks_cluster"):
        for vpc in c.children("vpc_config"):
            if _lit(vpc, "endpoint_public_access", env) is not False:
                cidrs = vpc.get("public_access_cidrs")
                v = _resolve(cidrs, env).literal() if cidrs is not None else None
                if cidrs is None or v == [] or _world_cidr([cidrs], env):
                    out.append(_f("eks-hardening", irel, vpc.line, "eks-public", _ref(c)))
    return out


def eks_hardening(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    out.extend(_eks_public(irel, blocks, locs))
    for c in _resources(blocks, "aws_eks_cluster"):
        res = _ref(c)
        enc = c.children("encryption_config")
        ok = any("secrets" in _as_list(_lit(e, "resources", locs)) and e.children("provider")
                 and e.children("provider")[0].get("key_arn") is not None for e in enc)
        if not ok:
            out.append(_f("eks-hardening", irel, enc[0].line if enc else c.line, "eks-secrets", res))
        lt = c.get("enabled_cluster_log_types")
        v = _resolve(lt, locs).literal() if lt is not None else None
        if lt is None or (isinstance(v, list) and not set(EKS_LOG_TYPES) <= set(v)) or \
                (v is None and lt.raw.strip() in ("[]", "null")):
            out.append(_f("eks-hardening", irel, lt.line if lt else c.line, "eks-logs", res))
    for t in _resources(blocks, "aws_launch_template"):
        md = t.children("metadata_options")
        if md and _lit(md[0], "http_endpoint", locs) == "disabled":
            continue
        if not md or _lit(md[0], "http_tokens", locs) != "required":
            a = md[0].get("http_tokens") if md else None
            out.append(_f("eks-hardening", irel, a.line if a else (md[0].line if md else t.line), "eks-imds", _ref(t)))
    for ng in _resources(blocks, "aws_eks_node_group"):
        if not ng.children("launch_template"):
            out.append(_f("eks-hardening", irel, ng.line, "eks-nodegroup-lt", _ref(ng)))
    return out


def ecr_hardening(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    for r in _resources(blocks, "aws_ecr_repository"):
        if _lit(r, "image_tag_mutability", _locals(blocks)) != "IMMUTABLE":
            a = r.get("image_tag_mutability")
            out.append(_f("ecr-hardening", irel, a.line if a else r.line, "ecr-mutable", _ref(r)))
    return out


def _public_routes(cfg: dict) -> set:
    out = set()
    for r in cfg.get("public_routes") or []:
        parts = str(r).split(None, 1)
        if len(parts) == 2:
            out.add((parts[0].upper(), parts[1].strip()))
        elif parts:
            out.add(("", parts[0].strip()))  # es. "$default"
    return out


def _is_public(method: Optional[str], path: Optional[str], cfg: dict) -> bool:
    if path is None:
        return False
    pub = _public_routes(cfg)
    m = (method or "").upper()
    return (m, path) in pub or ("ANY", path) in pub


def _no_auth(a: Optional[hcl.Attr], locs, default_none: bool) -> bool:
    """True se l'attributo di autorizzazione è "NONE", assente (quando il default è NONE) o non letterale."""
    if a is None:
        return default_none
    v = _resolve(a, locs).literal()
    return not isinstance(v, str) or v.upper() == "NONE"


def api_hardening(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for r in _resources(blocks, "aws_apigatewayv2_route"):
        a = r.get("authorization_type")
        if _no_auth(a, locs, True):
            rk = _lit(r, "route_key", locs)
            method, path = (None, None)
            if isinstance(rk, str):
                parts = rk.split(None, 1)
                method, path = (parts[0], parts[1]) if len(parts) == 2 else ("", rk)
            if not _is_public(method, path, cfg):
                out.append(_f("api-hardening", irel, a.line if a else r.line, "api-auth", _ref(r),
                              route=f"route \"{rk}\"" if isinstance(rk, str) else "route"))
    for s in _resources(blocks, "aws_api_gateway_stage", "aws_apigatewayv2_stage"):
        als = s.children("access_log_settings")
        if not als or als[0].get("destination_arn") is None:
            out.append(_f("api-hardening", irel, s.line, "api-logs", _ref(s)))
        if s.labels[0] == "aws_apigatewayv2_stage":
            drs = s.children("default_route_settings")
            if not drs or not all(_throttle_ok(drs[0].get(k)) for k in ("throttling_rate_limit",
                                                                        "throttling_burst_limit")):
                out.append(_f("api-hardening", irel, drs[0].line if drs else s.line, "api-throttle-v2", _ref(s)))
    return out


def _throttle_ok(a: Optional[hcl.Attr]) -> bool:
    """Limite di throttling impostato: numero > 0 (-1 lo disattiva) o espressione (valore per ambiente)."""
    if a is None or a.raw.strip() == "null":
        return False
    v = a.literal()
    if v is None:
        return True
    return isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0


def lambda_hardening(irel: str, blocks: List[hcl.Block], text: str, cfg: dict) -> List[Finding]:
    out: List[Finding] = []
    locs = _locals(blocks)
    for fn in _resources(blocks, "aws_lambda_function"):
        res = _ref(fn)
        for env in fn.children("environment"):
            var_attr = _resolve(env.get("variables"), locs)
            for name, a in ((var_attr.entries() or {}) if var_attr is not None else {}).items():
                if not any(s in name.upper() for s in LAMBDA_SENSITIVE):
                    continue
                v = _resolve(a, locs).literal()
                if isinstance(v, (str, int, float)) and not isinstance(v, bool) and str(v) \
                        and not str(v).startswith("arn:"):
                    out.append(_f("lambda-hardening", irel, a.line, "lambda-env", res, name=name))
        tc = fn.children("tracing_config")
        mode = _resolve(tc[0].get("mode"), locs) if tc else None
        # "PassThrough" equivale all'assenza: la funzione non avvia il tracing
        if mode is None or mode.raw.strip() == "null" or mode.literal() not in ("Active", None):
            out.append(_f("lambda-hardening", irel, tc[0].line if tc else fn.line, "lambda-tracing", res))
    return out


AWS_RULES: List[Callable[[str, List[hcl.Block], str, dict], List[Finding]]] = [
    s3_private, cloudfront_https, lb_https, sg_open, iam_least_privilege, kms_rotation, logs_retention,
    eks_hardening, ecr_hardening, api_hardening, lambda_hardening,
]


# ---------------------------------------------------------------- regole d'insieme (cartella Terraform)

Files = List[Tuple[str, List[hcl.Block]]]


def _tops(files: Files) -> List[Tuple[str, hcl.Block, Dict[str, hcl.Attr]]]:
    """(irel, blocco di primo livello, locals del file) dei file Terraform (non tfvars)."""
    out = []
    for irel, blocks in files:
        if irel.lower().endswith(TFVARS_EXT):
            continue
        locs = _locals(blocks)
        out.extend((irel, b, locs) for b in blocks)
    return out


def _of_type(tops, *types: str):
    return [(irel, b, locs) for irel, b, locs in tops
            if b.type == "resource" and b.labels[:1] and b.labels[0] in types]


def _companion_of(comp: hcl.Block, target: hcl.Block, attr: str, attrs: Tuple[str, ...], name_attr: str) -> bool:
    """Il blocco compagno referenzia `target` nell'attributo `attr`: `<tipo>.<nome>[indice].<id|…>`,
    `each.value.<…>` con `for_each = <tipo>.<nome>`, o lo stesso nome letterale (`name_attr` del target)."""
    a = comp.get(attr)
    if a is None or len(target.labels) < 2:
        return False
    rtype, name = target.labels[0], target.labels[1]
    raw = a.raw.strip()
    if _refers(raw, rtype, name, attrs):
        return True
    fe = comp.get("for_each")
    if raw in tuple(f"each.value.{x}" for x in attrs) and fe is not None and \
            re.fullmatch(rf"{re.escape(rtype)}\.{re.escape(name)}", fe.raw.strip()):
        return True
    lit, own = a.literal(), _lit(target, name_attr)
    return isinstance(lit, str) and lit == own


def _bucket_ref(comp: hcl.Block, bucket: hcl.Block) -> bool:
    return _companion_of(comp, bucket, "bucket", ("id", "bucket"), "bucket")


def _tls_deny(stmts: List[Stmt]) -> bool:
    for s in stmts:
        if _is_allow(s.effect):
            continue
        for test, key, values in s.conditions or []:
            if test.lower() == "bool" and key.lower() == "aws:securetransport" and \
                    any(v is False or (isinstance(v, str) and v.lower() == "false") for v in values):
                return True
    return False


def s3_private_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    buckets = _of_type(tops, "aws_s3_bucket")
    if not buckets:
        return []
    docs = {b.labels[1]: b for _, b, _ in tops if b.type == "data" and b.labels[:1] == ["aws_iam_policy_document"]
            and len(b.labels) > 1}
    pabs = _of_type(tops, "aws_s3_bucket_public_access_block")
    sses = [(i, b, l) for i, b, l in _of_type(tops, "aws_s3_bucket_server_side_encryption_configuration")
            if b.children("rule")]
    vers = _of_type(tops, "aws_s3_bucket_versioning")
    pols = _of_type(tops, "aws_s3_bucket_policy")
    out: List[Finding] = []
    for irel, bk, _ in buckets:
        ref = _ref(bk)

        def has(comps) -> bool:
            return any(_bucket_ref(c, bk) for _, c, _ in comps)

        if not has(pabs):
            out.append(_f("s3-private", irel, bk.line, "s3-missing-pab", ref, ref=ref))
        if not has(sses):
            out.append(_f("s3-private", irel, bk.line, "s3-missing-sse", ref, ref=ref))
        tls = False
        for _, p, locs in pols:
            if _bucket_ref(p, bk) and p.get("policy") is not None:
                stmts, _ = _policy_statements(p.get("policy"), locs, docs)
                tls = tls or _tls_deny(stmts or [])
        if not tls:
            out.append(_f("s3-private", irel, bk.line, "s3-missing-tls", ref, ref=ref))
        if not has(vers):
            out.append(_f("s3-private", irel, bk.line, "s3-missing-versioning", ref, ref=ref))
    return out


s3_private_project.rule = "s3-private"


def cloudfront_https_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    sources = _of_type(tops, "aws_cloudwatch_log_delivery_source")
    deliveries = _of_type(tops, "aws_cloudwatch_log_delivery")
    out: List[Finding] = []
    for irel, d, _ in _of_type(tops, "aws_cloudfront_distribution"):
        if d.children("logging_config") and d.children("logging_config")[0].get("bucket") is not None:
            continue
        name = d.labels[1] if len(d.labels) > 1 else ""
        ok = False
        for _, s, _ in sources:
            ra = s.get("resource_arn")
            if ra is not None and _refers(ra.raw, "aws_cloudfront_distribution", name, ("arn",)):
                sname = s.labels[1] if len(s.labels) > 1 else ""
                ok = ok or any(dl.get("delivery_source_name") is not None and
                               _refers(dl.get("delivery_source_name").raw, "aws_cloudwatch_log_delivery_source",
                                       sname, ("name",)) for _, dl, _ in deliveries)
        if not ok:
            out.append(_f("cloudfront-https", irel, d.line, "cf-logging", _ref(d), ref=_ref(d)))
    return out


cloudfront_https_project.rule = "cloudfront-https"


def lb_https_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    http = [b for _, b, locs in _of_type(tops, "aws_lb_listener", "aws_alb_listener")
            if _listener_protocol(b, locs) == "HTTP"]
    out: List[Finding] = []
    for irel, r, locs in _of_type(tops, "aws_lb_listener_rule", "aws_alb_listener_rule"):
        la = r.get("listener_arn")
        if la is None:
            continue
        if any(_refers(la.raw, l.labels[0], l.labels[1], ("arn", "id")) for l in http if len(l.labels) > 1) and \
                not _redirects_to_https(r.children("action"), locs):
            out.append(_f("lb-https", irel, r.line, "lb-rule-http", _ref(r)))
    return out


lb_https_project.rule = "lb-https"


def ecr_hardening_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    repos = _of_type(tops, "aws_ecr_repository")
    if not repos:
        return []
    enhanced = any(_lit(b, "scan_type", locs) == "ENHANCED"
                   for _, b, locs in _of_type(tops, "aws_ecr_registry_scanning_configuration"))
    policies = _of_type(tops, "aws_ecr_lifecycle_policy")
    out: List[Finding] = []
    for irel, r, locs in repos:
        isc = r.children("image_scanning_configuration")
        if not enhanced and not (isc and _is_true(isc[0], "scan_on_push", locs)):
            out.append(_f("ecr-hardening", irel, r.line, "ecr-scan", _ref(r)))
        if not any(_companion_of(p, r, "repository", ("name", "id"), "name") for _, p, _ in policies):
            out.append(_f("ecr-hardening", irel, r.line, "ecr-lifecycle", _ref(r), ref=_ref(r)))
    return out


ecr_hardening_project.rule = "ecr-hardening"


def _rest_path(raw: str, resources: Dict[str, hcl.Block], depth: int = 0) -> Optional[str]:
    raw = raw.strip()
    if depth > 30:
        return None
    if re.fullmatch(r"aws_api_gateway_rest_api\.[\w-]+(\[[^\]]*\])?\.root_resource_id", raw):
        return "/"
    m = re.fullmatch(r"aws_api_gateway_resource\.([\w-]+)(\[[^\]]*\])?\.id", raw)
    if not m or m.group(1) not in resources:
        return None
    res = resources[m.group(1)]
    part = _lit(res, "path_part")
    parent = res.get("parent_id")
    if not isinstance(part, str) or parent is None:
        return None
    base = _rest_path(parent.raw, resources, depth + 1)
    return None if base is None else base.rstrip("/") + "/" + part


def api_hardening_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    resources = {b.labels[1]: b for _, b, _ in _of_type(tops, "aws_api_gateway_resource") if len(b.labels) > 1}
    out: List[Finding] = []
    for irel, m, locs in _of_type(tops, "aws_api_gateway_method"):
        a = m.get("authorization")
        if not _no_auth(a, locs, True):
            continue
        method = _lit(m, "http_method", locs)
        rid = m.get("resource_id")
        path = _rest_path(rid.raw, resources) if rid is not None else None
        if not _is_public(method if isinstance(method, str) else None, path, cfg):
            route = f"{method} {path}" if isinstance(method, str) and path else "metodo"
            out.append(_f("api-hardening", irel, a.line if a else m.line, "api-auth", _ref(m), route=route))
    settings = _of_type(tops, "aws_api_gateway_method_settings")
    plans = _of_type(tops, "aws_api_gateway_usage_plan")
    for irel, s, _ in _of_type(tops, "aws_api_gateway_stage"):
        name = s.labels[1] if len(s.labels) > 1 else ""
        ok = False
        for _, ms, _ in settings:
            sn = ms.get("stage_name")
            st = ms.children("settings")
            if sn is not None and _refers(sn.raw, "aws_api_gateway_stage", name, ("stage_name",)) and st and \
                    all(_throttle_ok(st[0].get(k)) for k in ("throttling_rate_limit", "throttling_burst_limit")):
                ok = True
        for _, p, _ in plans:
            ts = p.children("throttle_settings")
            if ts and all(_throttle_ok(ts[0].get(k)) for k in ("rate_limit", "burst_limit")) and any(
                    st.get("stage") is not None and _refers(st.get("stage").raw, "aws_api_gateway_stage", name,
                                                            ("stage_name",)) for st in p.children("api_stages")):
                ok = True
        if not ok:
            out.append(_f("api-hardening", irel, s.line, "api-throttle", _ref(s), ref=_ref(s)))
    return out


api_hardening_project.rule = "api-hardening"


def _norm_expr(raw: str) -> str:
    return re.sub(r"\s+", "", raw)


def lambda_hardening_project(files: Files, cfg: dict) -> List[Finding]:
    tops = _tops(files)
    groups = [g for _, g, _ in _of_type(tops, "aws_cloudwatch_log_group") if g.get("retention_in_days") is not None]
    out: List[Finding] = []
    for irel, fn, locs in _of_type(tops, "aws_lambda_function"):
        name = fn.labels[1] if len(fn.labels) > 1 else ""
        fname = fn.get("function_name")
        expected = set()
        if fname is not None:
            lit = fname.literal()
            raw = fname.raw.strip()
            if isinstance(lit, str):
                expected.add(_norm_expr(json.dumps("/aws/lambda/" + lit)))
            elif raw.startswith('"') and raw.endswith('"'):
                expected.add(_norm_expr('"/aws/lambda/' + raw[1:]))
            else:
                expected.add(_norm_expr('"/aws/lambda/${' + raw + '}"'))
        lc = fn.children("logging_config")
        custom = lc[0].get("log_group") if lc else None
        ok = False
        for g in groups:
            gname = g.get("name")
            if gname is None:
                continue
            gl = g.labels[1] if len(g.labels) > 1 else ""
            if custom is not None and (_refers(custom.raw, "aws_cloudwatch_log_group", gl, ("name", "id")) or
                                       _norm_expr(custom.raw) == _norm_expr(gname.raw)):
                ok = True
            elif custom is None and (_norm_expr(gname.raw) in expected or (
                    "/aws/lambda/" in gname.raw and _mentions(gname.raw, "aws_lambda_function", name))):
                ok = True
        if not ok:
            out.append(_f("lambda-hardening", irel, fn.line, "lambda-logs", _ref(fn)))
    return out


lambda_hardening_project.rule = "lambda-hardening"


def _dir_vars(files: Files) -> Dict[str, hcl.Attr]:
    """{"var.<nome>": valore} della cartella: default delle variabili, sovrascritti dai tfvars della cartella
    (terraform.tfvars, poi *.auto.tfvars in ordine; l'ultimo vince)."""
    env: Dict[str, hcl.Attr] = {}
    for _, b, _ in _tops(files):
        if b.type == "variable" and b.labels and b.get("default") is not None:
            env[f"var.{b.labels[0]}"] = b.get("default")
    names = ("terraform.tfvars", "terraform.tfvars.json")
    tfvars = sorted((f for f in files if posixpath.basename(f[0]).lower() in names
                     or f[0].lower().endswith((".auto.tfvars", ".auto.tfvars.json"))),
                    key=lambda f: _tfvars_order(f[0]))
    for _, blocks in tfvars:
        for b in blocks:
            env.update((f"var.{k}", a) for k, a in b.attrs.items())
    return env


def var_values_project(files: Files, cfg: dict) -> List[Finding]:
    """sg-open e l'endpoint pubblico di EKS con `var.*` risolte (default o tfvars della stessa cartella): segnala solo
    ciò che il controllo per file, senza variabili, non ha già visto. Una variabile senza default né valore resta
    non verificabile (nessun finding)."""
    dvars = _dir_vars(files)
    if not dvars:
        return []
    out: List[Finding] = []
    for irel, blocks in files:
        if irel.lower().endswith(TFVARS_EXT):
            continue
        locs = _locals(blocks)
        env = {**dvars, **locs}
        for check in (_sg_findings, _eks_public):
            plain = {(f.path, f.line, f.rule) for f in check(irel, blocks, locs)}
            out.extend(f for f in check(irel, blocks, env) if (f.path, f.line, f.rule) not in plain)
    return out


var_values_project.rules = ("sg-open", "eks-hardening")


# ---------------------------------------------------------------- toggle di prod (moduli ↔ tfvars degli stack)

def _module_dir(stack_dir: str, source) -> Optional[str]:
    if not isinstance(source, str) or not source.startswith(("./", "../")):
        return None
    return posixpath.normpath(posixpath.join(stack_dir, source))


def _tfvars_order(irel: str) -> Tuple[int, str]:
    base = posixpath.basename(irel).lower()
    return (0 if base == "terraform.tfvars" else 1 if base == "terraform.tfvars.json" else 2, base)


def _hint(var: str, t: ProdToggle) -> str:
    """Valore da suggerire per attivare il toggle: true per i booleani, altrimenti l'ARN."""
    return "true" if var.endswith(("_enabled", "_protection")) or t.attr.startswith("enable_") else "<ARN>"


def _stack_var(stack_dir: str, files: Files, var: str, t: ProdToggle, stack: str) -> Optional[Finding]:
    """Valore in prod della variabile `var` dello stack: ultimo tfvars che la imposta, altrimenti il default."""
    names = ("terraform.tfvars", "terraform.tfvars.json")
    tfvars = sorted((f for f in files if posixpath.basename(f[0]).lower() in names
                     or f[0].lower().endswith((".auto.tfvars", ".auto.tfvars.json"))),
                    key=lambda f: _tfvars_order(f[0]))
    setter = None
    for irel, blocks in tfvars:
        for b in blocks:
            if b.get(var) is not None:
                setter = (irel, b.get(var))
    value = _hint(var, t)
    if setter is not None:
        if _truth(setter[1]) is False:
            return _f(t.rule, setter[0], setter[1].line, "prod-tfvars", "", what=t.what, stack=stack, var=var,
                      value=value)
        return None
    for irel, blocks in files:
        for b in blocks:
            if b.type == "variable" and b.labels[:1] == [var]:
                d = b.get("default")
                if d is not None and _truth(d) is not False:
                    return None
    return _f(t.rule, stack_dir + "/terraform.tfvars", 0, "prod-tfvars", "", what=t.what, stack=stack, var=var,
              value=value)


def prod_toggles(files: Files, cfg: dict) -> List[Finding]:
    """Ogni stack di prod che usa un modulo con toggle "solo prod" (PROD_TOGGLES) li attiva; idem per le risorse
    scritte nello stack che dipendono da una sua variabile."""
    dirs: Dict[str, Files] = {}
    for irel, blocks in files:
        dirs.setdefault(posixpath.dirname(irel), []).append((irel, blocks))

    def toggle_vars(dir_files: Files, allowed_only: bool) -> List[Tuple[str, ProdToggle]]:
        found: List[Tuple[str, ProdToggle]] = []
        dir_locals = _locals(b for _, b, _ in _tops(dir_files))  # locals di tutti i file della cartella
        for _, b, _ in _tops(dir_files):
            if b.type != "resource" or not b.labels:
                continue
            for t in _toggles_for(b.labels[0]):
                a = _resolve(b.get(t.attr), dir_locals)
                if a is None:
                    continue
                for v in VAR_RE.findall(a.raw):
                    if (v in t.variables or not allowed_only) and (v, t) not in found:
                        found.append((v, t))
        return found

    module_toggles = {d: toggle_vars(fs, True) for d, fs in dirs.items() if d.startswith("modules/")}
    out: List[Finding] = []
    for d, fs in sorted(dirs.items()):
        parts = d.split("/")
        if len(parts) != 3 or parts[0] != "envs" or parts[1] != "prod":
            continue
        stack = parts[2]
        checked = set()

        def check_var(var: str, t: ProdToggle) -> None:
            if var not in checked:
                checked.add(var)
                f = _stack_var(d, fs, var, t, stack)
                if f is not None:
                    out.append(f)

        for var, t in toggle_vars(fs, False):
            check_var(var, t)
        for irel, mb, locs in _tops(fs):
            if mb.type != "module":
                continue
            src = mb.get("source")
            mdir = _module_dir(d, src.literal() if src is not None else None)
            for var, t in module_toggles.get(mdir or "", []):
                arg = mb.get(var)
                if arg is None:
                    default_ok = any(b.type == "variable" and b.labels[:1] == [var] and b.get("default") is not None
                                     and _truth(b.get("default")) is not False
                                     for _, b, _ in _tops(dirs.get(mdir, [])))
                    if not default_ok:
                        out.append(_f(t.rule, d + "/terraform.tfvars", 0, "prod-tfvars", "", what=t.what,
                                      stack=stack, var=var,
                                      value=_hint(var, t)))
                    continue
                # letterale vero, var.<nome> verificata nei tfvars, o (per gli ARN) un riferimento a una risorsa;
                # ogni altra espressione (1 == 2, !true, local.off falso…) non è verificabile → finding
                val = _resolve(arg, locs)
                m = re.fullmatch(r"var\.([A-Za-z_][\w-]*)", val.raw.strip())
                truth = _truth(val)
                if m:
                    check_var(m.group(1), t)
                elif truth is True or (truth is None and _hint(var, t) == "<ARN>" and _pure_ref(val.raw.strip())):
                    continue
                else:
                    out.append(_f(t.rule, irel, arg.line, "prod-arg", mb.address(), what=t.what, var=var,
                                  raw=arg.raw.strip(), value=_hint(var, t)))
    return out


# copre più regole: i finding hanno la regola del toggle; in caso di errore interno uno per regola
prod_toggles.rules = tuple(dict.fromkeys(t.rule for t in PROD_TOGGLES))
prod_toggles.scope = "project"

AWS_PROJECT_RULES: List[Callable[[Files, dict], List[Finding]]] = [
    s3_private_project, cloudfront_https_project, lb_https_project, ecr_hardening_project, api_hardening_project,
    lambda_hardening_project, var_values_project, prod_toggles,
]

rules.PROVIDER_RULES["aws"] = AWS_RULES
rules.PROVIDER_PROJECT_RULES["aws"] = AWS_PROJECT_RULES
