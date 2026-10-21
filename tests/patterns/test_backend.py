"""Test specifici del pattern backend generato da un progetto kybes (fixture tests/fixtures/kybes-repo): tfvars
generati (3 handler, 1 job), arch_check strict a zero con api-coverage verde, operazione nuova senza rigenerare
bloccata dallo stop gate, Lambda con timeout 10 s, nessun segreto nelle variabili d'ambiente."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_patterns as tp  # noqa: E402

ROOT = tp.ROOT
SCRIPTS = tp.PLUGIN / "scripts"
sys.path.insert(0, str(ROOT / "tests" / "hooks"))
import test_stop_gate  # noqa: E402

generate = tp.generate
arch_check = tp.arch_check
rules = tp.rules
import hcl  # noqa: E402
import tools  # noqa: E402

ENVS = ["dev", "prod"]
NEW_OPERATION = '''  /v1/ordini/{id}:
    delete:
      operationId: annullaOrdine
      x-kybes-handler: ordini/functions/crea-ordine
      parameters:
        - name: id
          in: path
          required: true
          schema: { type: string }
      responses:
        "204": { description: Annullato }
'''


def build(proj: Path, extra: dict = None) -> dict:
    """Fixture kybes + network, secrets, ecr, eks e backend per dev e prod; ritorna il risultato del backend."""
    cfg = tp.make_project(proj, kybes=True)
    for p in ("network", "secrets", "ecr", "eks"):
        tp.generate_pattern(proj, cfg, "aws", p)
    return generate.generate(proj, cfg, "aws", "backend", ENVS, {"oidc_audience": "acme-api", **(extra or {})})


def tfvars(path: Path) -> dict:
    return {k: a.literal() for k, a in hcl.parse_tfvars(path.read_text(encoding="utf-8"), path.name).items()}


def block(text: str, header: str) -> str:
    m = re.search(re.escape(header) + r" \{(.*?)\n\}", text, re.S)
    assert m, f"blocco assente: {header}"
    return m.group(1)


def console_paths(terraform: str, d: Path, module_text: str, servers: str, path: str) -> dict:
    """Valuta con `terraform console` (config senza provider, riferimenti alle risorse sostituiti) i `local` del body
    OpenAPI del modulo su uno schema minimo: percorsi del body, percorso dell'integrazione, chiave della route."""
    start = module_text.index("  # ------------------------------------------------------------ OpenAPI")
    body = module_text[start:module_text.index("\n}\n", start)]
    body = body.replace("aws_lb.ms[0].dns_name", '"nlb"').replace("aws_api_gateway_vpc_link.ms[0].id", '"vl"')
    body = re.sub(r"aws_lambda_alias\.this\[[^\]]+\]\.invoke_arn", '"arn:fn"', body)
    (d / "openapi.yaml").write_text(f"openapi: 3.0.3\n{servers}paths:\n  {path}:\n    get:\n"
                                    "      x-kybes-handler: ordini/functions/lista\n", encoding="utf-8")
    (d / "main.tf").write_text(
        'variable "handlers" {\n  default = { "ordini/functions/lista" = { kind = "function" } }\n}\n'
        'variable "routes" {\n  default = {}\n}\nvariable "public_routes" {\n  default = []\n}\n'
        'variable "authorizer" {\n  default = "lambda"\n}\nvariable "cognito_user_pool_arn" {\n  default = ""\n}\n'
        'variable "openapi_file" {\n  default = "openapi.yaml"\n}\nlocals {\n'
        '  methods        = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]\n'
        '  auth_scheme    = "kynfra-authorizer"\n  authorizer_key = "authorizer"\n'
        '  use_lambda_jwt = true\n  ms_ports       = {}\n' + body + "\n}\n", encoding="utf-8")
    env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0", TF_DATA_DIR=str(d / ".terraform"))
    subprocess.run([terraform, "init", "-input=false", "-backend=false"], cwd=d, env=env, check=True,
                   capture_output=True, timeout=120)
    expr = ('jsonencode({ paths = keys(local.paths), route_path = values(local.operations)[0].path, '
            'routes_key = keys(local.operations)[0] })')
    r = subprocess.run([terraform, "console"], cwd=d, env=env, input=expr, capture_output=True, text=True,
                       timeout=120, check=True)
    return json.loads(json.loads(r.stdout.strip()))


class BackendPatternTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="kynfra-backend-")
        cls.proj = Path(cls._tmp.name)
        cls.result = build(cls.proj)
        cls.cfg = rules.load_config(cls.proj)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def module(self, name: str) -> str:
        return (self.proj / "infra/modules/backend" / name).read_text(encoding="utf-8")

    def stack(self, env: str, name: str) -> str:
        return (self.proj / "infra/envs" / env / "backend" / name).read_text(encoding="utf-8")

    def test_backend_from_kybes_fixture(self):
        self.assertEqual(self.result["missing_requires"], [])
        for env in ENVS:
            stack = self.proj / "infra/envs" / env / "backend"
            gen = tfvars(stack / "handlers.auto.tfvars")
            self.assertEqual(sorted(gen["handlers"]), ["magazzino/ms/giacenze", "ordini/functions/crea-ordine",
                                                       "ordini/functions/lista-ordini"])
            self.assertEqual(gen["handlers"]["ordini/functions/crea-ordine"],
                             {"kind": "function", "runtime": "python3.12", "handler": "handler.handler"})
            self.assertEqual(gen["handlers"]["ordini/functions/lista-ordini"],
                             {"kind": "function", "runtime": "nodejs20.x", "handler": "dist/index.handler"})
            self.assertEqual(gen["handlers"]["magazzino/ms/giacenze"]["kind"], "ms")
            self.assertEqual(gen["routes"], {
                "GET /v1/ordini": "ordini/functions/lista-ordini",
                "POST /v1/ordini": "ordini/functions/crea-ordine",
                "GET /v1/magazzino/giacenze": "magazzino/ms/giacenze",
                "GET /v1/magazzino/giacenze/{sku}": "magazzino/ms/giacenze"})
            # security: [] senza public_routes in config: resta dietro l'authorizer (e il generatore lo segnala)
            self.assertEqual(gen["public_routes"], [])
            self.assertEqual(tfvars(stack / "jobs.auto.tfvars")["jobs"], {"sync-giacenze": {"trigger": "sqs"}})
            tv = tfvars(stack / "terraform.tfvars")
            # valori dedotti dal progetto: nel file rigenerato kybes.auto.tfvars, non in terraform.tfvars
            kv = tfvars(stack / "kybes.auto.tfvars")
            self.assertIs(kv["has_db"], True)
            for name in ("has_db", "kybes_root", "openapi_path"):
                self.assertNotIn(name, tv)
            # lo schema si raggiunge dallo stack con kybes_root + openapi_path (relativo a kybes.root)
            self.assertTrue((stack / kv["kybes_root"] / kv["openapi_path"]).resolve().samefile(
                self.proj / "schemas/openapi.yaml"))
            self.assertEqual(tv["oidc_issuer"], "https://login.example.com")
        self.assertTrue(any("GET /v1/magazzino/giacenze" in s and "public_routes" in s
                            for s in self.result["next_steps"]))
        self.assertTrue(any("repositories=magazzino-giacenze,sync-giacenze" in s for s in self.result["next_steps"]))
        self.assertEqual(tfvars(self.proj / "infra/envs/prod/backend/terraform.tfvars")["waf_enabled"], True)
        findings = arch_check.run(self.proj, self.cfg)
        self.assertEqual([f.format() for f in findings], [], "arch_check --strict (api-coverage compresa)")
        # lo stesso con arch_check.py --strict da riga di comando
        r = subprocess.run([sys.executable, "-B", str(SCRIPTS / "arch_check.py"), str(self.proj), "--strict"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_backend_has_db_regenerated(self):
        """I valori dedotti dal progetto (has_db, kybes_root, openapi_path) stanno in kybes.auto.tfvars, rigenerato
        senza --force: aggiungere schemas/db più tardi porta has_db a true."""
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-db-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            shutil.rmtree(proj / "schemas/db")
            generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            kv = proj / "infra/envs/dev/backend/kybes.auto.tfvars"
            self.assertIs(tfvars(kv)["has_db"], False)
            (proj / "schemas/db").mkdir()
            (proj / "schemas/db/Ordini.yaml").write_text("table: Ordini\n", encoding="utf-8")
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            self.assertIn("infra/envs/dev/backend/kybes.auto.tfvars", res["regenerated"])
            self.assertIs(tfvars(kv)["has_db"], True)
            self.assertIn("infra/envs/dev/backend/terraform.tfvars", res["skipped"])

    def test_backend_minor_hardening(self):
        text = self.module("main.tf")
        variables = self.module("variables.tf")
        # {proxy+} nel percorso della risorsa, {proxy} nell'URI dell'integrazione
        self.assertIn('replace(o.path, "+}", "}")', text)
        # target group: porta nel nome e create_before_destroy
        tg = block(text, 'resource "aws_lb_target_group" "ms"')
        self.assertRegex(tg, r'\n  name\s+= "\$\{local\.name\}-\$\{substr\(sha1\(each\.key\), 0, 6\)\}-\$\{var\.ms_target_port\}"')
        self.assertIn("create_before_destroy = true", tg)
        # nomi di Lambda e ruoli entro 64 caratteri, job senza collisione con <contesto>-<ms>
        self.assertIn("<= 64", variables)
        self.assertIn("collide con un microservizio", variables)
        # bucket dei log unico: NLB e access log S3 del bucket degli artefatti
        self.assertIn('resource "aws_s3_bucket_logging" "artifacts"', text)
        self.assertIn("logging.s3.amazonaws.com", text)
        baseline = json.loads((tp.PLUGIN / "templates/scanner-baseline.json").read_text(encoding="utf-8"))
        ids = {e["id"] for e in baseline["checkov"] if e["paths"] == ["modules/backend/**"]}
        self.assertNotIn("CKV_AWS_297", ids)
        # oidc_audience facoltativo con Cognito
        entry = generate.load_pattern("aws", "backend")
        self.assertFalse(entry["inputs"]["oidc_audience"].get("required", True))
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-cog-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {
                "authorizer": "cognito",
                "cognito_user_pool_arn": "arn:aws:cognito-idp:eu-south-1:123456789012:userpool/eu-south-1_Abc123"})
            self.assertTrue(res["created"])
            self.assertFalse(any("oidc_audience" in s for s in res["next_steps"]))
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {})
            self.assertTrue(any("oidc_audience" in s for s in res["next_steps"]))

    def test_backend_db_engine_iam_auth_only(self):
        """IAM_AUTH di RDS Proxy: solo famiglie MYSQL (anche MariaDB) e POSTGRESQL; SQLSERVER rifiutato."""
        entry = generate.load_pattern("aws", "backend")
        self.assertEqual(entry["inputs"]["db_engine_family"]["choices"], ["POSTGRESQL", "MYSQL"])
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-eng-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            with self.assertRaisesRegex(generate.GenerateError, "db_engine_family"):
                generate.generate(proj, cfg, "aws", "backend", ["dev"],
                                  {"oidc_audience": "acme-api", "db_engine_family": "SQLSERVER"})
        variables = self.module("variables.tf")
        self.assertIn('contains(["POSTGRESQL", "MYSQL"], var.db_engine_family)', variables)
        self.assertNotIn("SQLSERVER", self.module("main.tf") + variables + self.stack("dev", "variables.tf"))
        # nessun riferimento residuo al segreto gestito da RDS; utenti IAM documentati per PostgreSQL e MySQL
        texts = [self.module("variables.tf"), self.stack("dev", "variables.tf"),
                 (tp.PLUGIN / "scripts/generate.py").read_text(encoding="utf-8"),
                 json.dumps(entry, ensure_ascii=False)]
        for t in texts:
            self.assertNotIn("manage_master_user_password", t)
            self.assertNotIn("segreto gestito da RDS", t)
        skill = (tp.PLUGIN / "skills/create-backend-infra-aws/SKILL.md").read_text(encoding="utf-8")
        for needle in ("GRANT rds_iam", "IDENTIFIED WITH AWSAuthenticationPlugin AS 'RDS'", "REQUIRE SSL",
                       "iam_database_authentication_enabled = true"):
            self.assertIn(needle, skill)
        self.assertIn("iam_database_authentication_enabled = true", entry["inputs"]["db_instance_identifier"]["help"])
        # limite di <project>-<env>: 19 caratteri solo con microservizi (target group dell'NLB), 23 altrimenti
        self.assertIn("? 19 : 23", variables)

    def test_backend_job_name_collision(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-coll-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            (proj / "jobs/magazzino-giacenze").mkdir()
            (proj / "jobs/magazzino-giacenze/Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            with self.assertRaisesRegex(generate.GenerateError, "magazzino-giacenze"):
                generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})

    def test_backend_shared_apigw_account(self):
        """R40: il ruolo CloudWatch di API Gateway (singleton per account) sta solo nello stack condiviso
        envs/shared/apigw-account, da applicare prima degli stack backend."""
        shared = self.proj / "infra/envs/shared/apigw-account"
        main = (shared / "main.tf").read_text(encoding="utf-8")
        self.assertIn('resource "aws_api_gateway_account" "this"', main)
        self.assertIn("AmazonAPIGatewayPushToCloudWatchLogs", main)
        # un solo ruolo per account, anche tra progetti diversi
        self.assertIn('name = "kynfra-apigateway-cloudwatch"', main)
        self.assertTrue(any("envs/shared/apigw-account" in s and "salta" in s for s in self.result["next_steps"]))
        self.assertIn('key          = "acme/shared/apigw-account.tfstate"',
                      (shared / "backend.tf").read_text(encoding="utf-8"))
        for path in (self.proj / "infra").glob("**/*.tf"):
            if "apigw-account" not in path.parts:
                self.assertNotIn("aws_api_gateway_account", path.read_text(encoding="utf-8"), str(path))
        steps = self.result["next_steps"]
        first_shared = next(i for i, x in enumerate(steps) if "envs/shared/apigw-account" in x)
        first_backend = next(i for i, x in enumerate(steps) if "envs/<env>/backend &&" in x)
        self.assertLess(first_shared, first_backend)
        self.assertIn("infra/envs/shared/apigw-account/main.tf", self.result["created"])

    def test_backend_requires_eks_and_ecr_with_workloads(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-req-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            self.assertEqual(res["missing_requires"], ["network", "secrets", "ecr", "eks"])
            # senza ms/ né jobs/ bastano network e secrets
            shutil.rmtree(proj / "services/magazzino")
            shutil.rmtree(proj / "jobs")
            schema = proj / "schemas/openapi.yaml"
            text = schema.read_text(encoding="utf-8")
            schema.write_text(text[:text.index("  /v1/magazzino/giacenze:")], encoding="utf-8")
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            self.assertEqual(res["missing_requires"], ["network", "secrets"])
            self.assertEqual(res["regenerated"], ["infra/envs/dev/backend/handlers.auto.tfvars",
                                                  "infra/envs/dev/backend/jobs.auto.tfvars"])
            self.assertEqual(tfvars(proj / "infra/envs/dev/backend/jobs.auto.tfvars")["jobs"], {})

    def test_backend_new_operation_detected(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-op-") as d:
            proj = Path(d) / "proj"
            proj.mkdir()
            build(proj)
            cfg = rules.load_config(proj)
            self.assertEqual(arch_check.run(proj, cfg), [])
            schema = proj / "schemas/openapi.yaml"
            schema.write_text(schema.read_text(encoding="utf-8") + NEW_OPERATION, encoding="utf-8")
            cov = [f for f in arch_check.run(proj, cfg) if f.rule == "api-coverage"]
            self.assertEqual(sorted({(f.path, f.severity) for f in cov}), [("schemas/openapi.yaml", "block")])
            self.assertTrue(all("DELETE /v1/ordini/{id}" in f.message for f in cov), [f.format() for f in cov])
            # lo stop gate (strumenti esterni finti) blocca sulla stessa regola
            fake = Path(d) / "bin"
            test_stop_gate.make_bin(fake)
            ev = {"cwd": str(proj), "hook_event_name": "Stop", "session_id": f"backend-{Path(d).name}",
                  "stop_hook_active": False}
            self.addCleanup(test_stop_gate.stop_gate.counter_path(ev, proj.resolve()).unlink, True)
            env = dict(os.environ, PATH=str(fake), FAKE_LOG=str(Path(d) / "calls.log"))
            r = subprocess.run([sys.executable, "-B", str(SCRIPTS / "stop_gate.py")], input=json.dumps(ev),
                               capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out.get("decision"), "block")
            self.assertIn("api-coverage", out["reason"])
            self.assertIn("DELETE /v1/ordini/{id}", out["reason"])
            # rigenerando (senza --force) la mappatura si aggiorna e la copertura torna verde
            res = generate.generate(proj, cfg, "aws", "backend", ENVS, {"oidc_audience": "acme-api"})
            self.assertIn("infra/envs/dev/backend/handlers.auto.tfvars", res["regenerated"])
            self.assertNotIn("infra/envs/dev/backend/terraform.tfvars", res["regenerated"])
            routes = tfvars(proj / "infra/envs/dev/backend/handlers.auto.tfvars")["routes"]
            self.assertEqual(routes["DELETE /v1/ordini/{id}"], "ordini/functions/crea-ordine")
            self.assertEqual(arch_check.run(proj, cfg), [])

    def test_backend_lambda_timeout_10(self):
        text = self.module("main.tf")
        blocks = hcl.parse(text, "main.tf")
        fns = [b for b in blocks if b.type == "resource" and b.labels[0] == "aws_lambda_function"]
        self.assertEqual(len(fns), 1)
        fn = fns[0]
        self.assertEqual(fn.get("timeout").literal(), 10)
        self.assertEqual(fn.get("for_each").raw.strip(), "local.lambdas")
        self.assertEqual(fn.children("tracing_config")[0].get("mode").literal(), "Active")
        self.assertRegex(fn.get("s3_bucket").raw, r"^aws_s3_bucket\.artifacts\.id$")
        self.assertIn("var.artifact_keys", fn.get("s3_key").raw)
        self.assertIn("var.artifact_sha256s", fn.get("source_code_hash").raw)
        # nessun altro timeout più lungo nascosto in una variabile
        self.assertNotIn('variable "lambda_timeout"', self.module("variables.tf"))
        alias = block(text, 'resource "aws_lambda_alias" "this"')
        self.assertRegex(alias, r"name\s*=\s*local\.alias_name")
        self.assertRegex(text, r'alias_name\s*=\s*"live"')
        perm = block(text, 'resource "aws_lambda_permission" "api"')
        self.assertIn("aws_api_gateway_rest_api.this.execution_arn", perm)
        self.assertRegex(perm, r'principal\s*=\s*"apigateway\.amazonaws\.com"')

    def test_backend_no_secrets_in_env(self):
        text = self.module("main.tf")
        env = block(text, 'resource "aws_lambda_function" "this"').split("environment {", 1)[1].split("\n  }", 1)[0]
        names = re.findall(r"\b([A-Z][A-Z0-9_]+)\s*=", env)
        self.assertEqual(sorted(set(names)), ["DB_PORT", "DB_PROXY_ENDPOINT", "DB_USER", "KYBES_ENVIRONMENT",
                                              "KYBES_HANDLER", "OIDC_AUDIENCE", "OIDC_ISSUER", "SECRET_ARNS"])
        # SECRET_ARNS contiene solo gli ARN dei segreti del contesto (lambda_secrets <- var.secret_arns)
        self.assertRegex(env, r"SECRET_ARNS = jsonencode\(local\.lambda_secrets\[each\.key\]\)")
        self.assertRegex(text, r"lambda_secrets = \{ for k, l in local\.lambdas : k => \[for n in "
                               r"lookup\(var\.context_secrets, l\.context, \[\]\) : var\.secret_arns\[n\]\] \}")
        # i valori vengono solo da variabili non riservate e da riferimenti (ARN, endpoint), mai da segreti
        self.assertEqual(sorted(set(re.findall(r"\bvar\.(\w+)", env))),
                         ["db_iam_user", "environment", "oidc_audience", "oidc_issuer"])
        self.assertEqual(sorted(set(re.findall(r"\baws_\w+\.\w+", env))), ["aws_db_proxy.this"])
        # niente valori di segreti in nessun file generato del backend
        for path in sorted((self.proj / "infra").glob("**/backend/**/*.tf*")):
            content = path.read_text(encoding="utf-8")
            self.assertNotRegex(content, r"secret_string|master_password\s*=|random_password", str(path))
        # RDS Proxy con IAM end-to-end: nessun segreto, il ruolo del proxy si collega al DB come db_iam_user
        proxy = block(text, 'resource "aws_db_proxy" "this"')
        self.assertRegex(proxy, r'default_auth_scheme\s*=\s*"IAM_AUTH"')
        self.assertRegex(proxy, r"require_tls\s*=\s*true")
        self.assertNotIn("auth {", proxy)
        self.assertNotIn("secret_arn", proxy)
        self.assertNotIn("master_user_secret", text)
        proxy_policy = block(text, 'resource "aws_iam_role_policy" "proxy"')
        self.assertIn('Action   = "rds-db:connect"', proxy_policy)
        self.assertIn("dbuser:${data.aws_db_instance.this[0].resource_id}/${var.db_iam_user}", proxy_policy)
        self.assertNotIn("secretsmanager", proxy_policy)
        skill = (tp.PLUGIN / "skills/create-backend-infra-aws/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("GRANT rds_iam", skill)
        self.assertIn("IAM_AUTH", skill)
        # le regole di kynfra sulle Lambda (variabili sensibili letterali, tracing, log group) non trovano nulla
        self.assertEqual([f.format() for f in arch_check.run(self.proj, self.cfg) if f.rule == "lambda-hardening"],
                         [])

    def test_backend_api_from_openapi(self):
        text = self.module("main.tf")
        self.assertIn("openapi_doc = yamldecode(file(var.openapi_file))", text)
        api = block(text, 'resource "aws_api_gateway_rest_api" "this"')
        self.assertRegex(api, r"body\s*=\s*jsonencode\(local\.openapi\)")
        self.assertIn('"x-amazon-apigateway-request-validator" = "all"', text)
        self.assertIn("validateRequestBody = true, validateRequestParameters = true", text)
        stage = block(text, 'resource "aws_api_gateway_stage" "this"')
        self.assertRegex(stage, r"xray_tracing_enabled\s*=\s*true")
        self.assertIn('correlationId      = "$context.requestId"', stage)
        settings = block(text, 'resource "aws_api_gateway_method_settings" "all"')
        for attr in ("throttling_rate_limit", "throttling_burst_limit"):
            self.assertRegex(settings, rf"{attr}\s*=\s*var\.{attr}")
        self.assertRegex(settings, r'logging_level\s*=\s*"INFO"')
        self.assertRegex(settings, r"metrics_enabled\s*=\s*true")
        waf = block(text, 'resource "aws_wafv2_web_acl_association" "this"')
        self.assertIn("aws_api_gateway_stage.this.arn", waf)
        out = self.stack("dev", "outputs.tf")
        for name in ("api_domain_name", "api_origin_path", "api_id", "stage_name", "lambda_function_names",
                     "artifacts_bucket", "queue_urls", "vpc_link_id"):
            self.assertIn(f'output "{name}"', out)
        # DLQ con maxReceiveCount 5 per ogni job
        queue = block(text, 'resource "aws_sqs_queue" "job"')
        self.assertIn("maxReceiveCount     = 5", queue)
        self.assertIn("aws_sqs_queue.dlq[each.key].arn", queue)

    def test_backend_stage_api_and_base_path(self):
        """R39: stage `api`, risorse = percorso base di servers[0].url + percorso dell'operazione (salvo che lo
        contenga già), api_origin_path vuoto; le chiavi di routes restano i percorsi dello schema."""
        text = self.module("main.tf")
        self.assertIn('stage_name     = "api"', text)
        self.assertNotIn('"v1"', text)
        self.assertRegex(block(self.module("outputs.tf"), 'output "api_origin_path"'), r'value\s*=\s*""')
        self.assertIn("module.backend.api_origin_path", self.stack("dev", "outputs.tf"))
        self.assertIn("local.resource_paths[p] => merge(", text)
        perm = block(text, 'resource "aws_lambda_permission" "api"')
        self.assertIn("/${local.stage_name}/*/*", perm)
        terraform = tools.resolve_binary(Path(os.environ.get("KYNFRA_TOOLS_PROJECT") or ROOT), "terraform")
        if not terraform:
            self.skipTest("terraform non disponibile: verifica dei percorsi con terraform console saltata")
        cases = {
            # servers con /v1 e percorsi senza: prefisso aggiunto
            "servers": ("servers:\n  - url: https://api.example.com/v1/\n", "/ordini", "/v1/ordini"),
            # percorsi che iniziano già con /v1: invariati
            "already": ("servers:\n  - url: https://api.example.com/v1\n", "/v1/ordini", "/v1/ordini"),
            # nessun percorso in servers (la fixture): invariati
            "none": ("servers:\n  - url: https://api.example.com\n", "/v1/ordini", "/v1/ordini"),
            "absent": ("", "/ordini/{id}", "/ordini/{id}"),
        }
        for name, (servers, path, expected) in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="kynfra-basepath-") as d:
                got = console_paths(terraform, Path(d), text, servers, path)
                self.assertEqual(got, {"paths": [expected], "route_path": expected,
                                       "routes_key": f"GET {path}"})

    def test_backend_schedule_and_errors(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-err-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            (proj / "jobs/sync-giacenze/job.yaml").write_text('schedule: "cron(0 2 * * ? *)"\n', encoding="utf-8")
            generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            self.assertEqual(tfvars(proj / "infra/envs/dev/backend/jobs.auto.tfvars")["jobs"],
                             {"sync-giacenze": {"trigger": "schedule", "schedule": "cron(0 2 * * ? *)"}})
            (proj / "jobs/sync-giacenze/job.yaml").write_text('schedule: "${evil}"\n', encoding="utf-8")
            with self.assertRaisesRegex(generate.GenerateError, "schedule"):
                generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            (proj / "jobs/sync-giacenze/job.yaml").unlink()
            # operazione ambigua (contesto ordini con due function, senza x-kybes-handler): mai un handler inventato
            schema = proj / "schemas/openapi.yaml"
            schema.write_text(schema.read_text(encoding="utf-8") + "  /v1/ordini/stato:\n    get:\n"
                              "      responses:\n        \"200\": { description: OK }\n", encoding="utf-8")
            with self.assertRaisesRegex(generate.GenerateError, "GET /v1/ordini/stato"):
                generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            no_kybes = rules.normalize_config({**tp.REFERENCE_CONFIG})
            with self.assertRaisesRegex(generate.GenerateError, "kybes"):
                generate.generate(proj, no_kybes, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})

    def test_backend_public_route_from_config(self):
        with tempfile.TemporaryDirectory(prefix="kynfra-backend-pub-") as d:
            proj = Path(d)
            cfg = tp.make_project(proj, kybes=True)
            cfg["public_routes"] = ["GET /v1/magazzino/giacenze", "GET /v1/ordini"]
            res = generate.generate(proj, cfg, "aws", "backend", ["dev"], {"oidc_audience": "acme-api"})
            # solo le operazioni con security: [] nello schema E in config restano senza authorizer
            self.assertEqual(tfvars(proj / "infra/envs/dev/backend/handlers.auto.tfvars")["public_routes"],
                             ["GET /v1/magazzino/giacenze"])
            self.assertFalse(any("restano dietro l'authorizer" in s for s in res["next_steps"]))


if __name__ == "__main__":
    unittest.main()
