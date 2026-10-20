"""Test del lettore kybes (kybes.py, mini_yaml.py) e della regola api-coverage."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "plugins" / "kynfra" / "scripts"))

import kybes  # noqa: E402
import mini_yaml  # noqa: E402
import rules  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "kybes-repo"

COMPLETE_HANDLERS = '''handlers = {
  "ordini/functions/lista-ordini" = { kind = "function", runtime = "nodejs20.x", handler = "dist/index.handler" }
  "ordini/functions/crea-ordine"  = { kind = "function", runtime = "python3.12", handler = "handler.handler" }
  "magazzino/ms/giacenze"         = { kind = "ms", runtime = "nodejs22.x", handler = "src/server.handler" }
}

routes = {
  "GET /v1/ordini"                   = "ordini/functions/lista-ordini"
  "POST /v1/ordini"                  = "ordini/functions/crea-ordine"
  "GET /v1/magazzino/giacenze"       = "magazzino/ms/giacenze"
  "GET /v1/magazzino/giacenze/{sku}" = "magazzino/ms/giacenze"
}
'''
COMPLETE_JOBS = 'jobs = {\n  "sync-giacenze" = { trigger = "sqs" }\n}\n'


class MiniYamlTest(unittest.TestCase):
    def test_mini_yaml_openapi_fixture(self):
        doc = mini_yaml.load((FIXTURE / "schemas" / "openapi.yaml").read_text(encoding="utf-8"))
        self.assertEqual(doc["openapi"], "3.0.3")
        self.assertEqual(doc["info"]["title"], "Gestionale API")
        self.assertEqual(doc["info"]["description"],
                         "Sorgente di verità per API Gateway.\nRiga due: con # non un commento.\n")
        self.assertEqual(doc["security"], [{"sso": []}])
        props = doc["components"]["schemas"]["Ordine"]
        self.assertEqual(props["required"], ["id", "cliente"])
        self.assertEqual(props["properties"]["id"], {"type": "string", "format": "uuid"})
        self.assertEqual(props["properties"]["righe"]["items"], {"$ref": "#/components/schemas/Riga"})
        self.assertEqual(doc["components"]["schemas"]["Riga"]["properties"]["quantita"]["minimum"], 1)
        get = doc["paths"]["/v1/ordini"]["get"]
        self.assertEqual(get["x-kybes-handler"], "ordini/functions/lista-ordini")
        self.assertEqual(get["responses"]["200"]["description"], "Elenco degli ordini")
        pub = doc["paths"]["/v1/magazzino/giacenze"]["get"]
        self.assertEqual(pub["security"], [])
        self.assertEqual(pub["description"], "Giacenze pubbliche, senza autenticazione.\n")
        params = doc["paths"]["/v1/magazzino/giacenze/{sku}"]["get"]["parameters"]
        self.assertEqual(params, [{"name": "sku", "in": "path", "required": True, "schema": {"type": "string"}}])

    def test_mini_yaml_scalars_and_json(self):
        doc = mini_yaml.load("a: ~\nb: true\nc: -2.5\nd: 'it''s'\ne: \"x\\ty\"\nf: [1, {g: h}]\ng:\n- 1\n- - 2\n")
        self.assertEqual(doc, {"a": None, "b": True, "c": -2.5, "d": "it's", "e": "x\ty",
                               "f": [1, {"g": "h"}], "g": [1, [2]]})
        self.assertEqual(mini_yaml.load('{"paths": {"/x": {"get": {}}}}'), {"paths": {"/x": {"get": {}}}})

    def test_mini_yaml_rejects_anchors_and_tags(self):
        for text in ("a: &x 1\nb: *x\n", "a: !!str 1\n", "a:\n  <<: *base\n"):
            with self.assertRaises(mini_yaml.MiniYamlError):
                mini_yaml.load(text)

    def test_mini_yaml_lines(self):
        _, lines = mini_yaml.load_with_lines("paths:\n  /x:\n    # c\n    get: {}\n")
        self.assertEqual(lines[("paths", "/x", "get")], 4)


class ReadProjectTest(unittest.TestCase):
    def setUp(self):
        self.p = kybes.read_project(FIXTURE)

    def test_read_project_fixture(self):
        ops = {(o.method, o.path): o for o in self.p.operations}
        self.assertEqual(len(self.p.operations), 4)
        self.assertEqual(ops[("GET", "/v1/ordini")].handler_ref, "ordini/functions/lista-ordini")
        self.assertEqual(ops[("GET", "/v1/ordini")].operation_id, "listaOrdini")
        self.assertTrue(ops[("GET", "/v1/magazzino/giacenze")].public)
        self.assertFalse(ops[("POST", "/v1/ordini")].public)
        self.assertGreater(ops[("POST", "/v1/ordini")].line, 0)
        self.assertEqual(sorted(self.p.handlers), ["magazzino/ms/giacenze", "ordini/functions/crea-ordine",
                                                   "ordini/functions/lista-ordini"])
        ms = self.p.handlers["magazzino/ms/giacenze"]
        self.assertEqual((ms.kind, ms.context, ms.name), ("ms", "magazzino", "giacenze"))
        py = self.p.handlers["ordini/functions/crea-ordine"]
        self.assertEqual((py.runtime, py.handler), ("python3.12", "handler.handler"))
        self.assertEqual(self.p.jobs, ["sync-giacenze"])
        self.assertTrue(self.p.has_db)

    def test_mapping_extension_wins(self):
        # l'estensione vince anche contro la convenzione: /v1/magazzino/... ma handler di ordini
        self.p.operations.append(kybes.Operation("DELETE", "/v1/magazzino/giacenze/{sku}", None,
                                                 "ordini/functions/crea-ordine", False))
        mapping, unresolved = kybes.resolve_mapping(self.p)
        self.assertEqual(mapping["GET /v1/ordini"], "ordini/functions/lista-ordini")
        self.assertEqual(mapping["POST /v1/ordini"], "ordini/functions/crea-ordine")
        self.assertEqual(mapping["DELETE /v1/magazzino/giacenze/{sku}"], "ordini/functions/crea-ordine")
        self.assertEqual(unresolved, [])

    def test_mapping_convention(self):
        mapping, _ = kybes.resolve_mapping(self.p)
        self.assertEqual(mapping["GET /v1/magazzino/giacenze"], "magazzino/ms/giacenze")
        self.assertEqual(mapping["GET /v1/magazzino/giacenze/{sku}"], "magazzino/ms/giacenze")

    def test_mapping_ambiguous_reported(self):
        amb = kybes.Operation("GET", "/v1/ordini/{id}", "leggiOrdine", None, False)
        unknown = kybes.Operation("GET", "/v1/fatture", None, None, False)
        self.p.operations.extend([amb, unknown])
        mapping, unresolved = kybes.resolve_mapping(self.p)
        self.assertNotIn("GET /v1/ordini/{id}", mapping)
        self.assertNotIn("GET /v1/fatture", mapping)
        self.assertEqual(unresolved, [amb, unknown])

    def test_runtime_from_package_json(self):
        h = self.p.handlers["ordini/functions/lista-ordini"]
        self.assertEqual(kybes.runtime_of(h), ("nodejs20.x", "dist/index.handler"))
        self.assertEqual(kybes.runtime_of(self.p.handlers["magazzino/ms/giacenze"]),
                         ("nodejs22.x", "src/server.handler"))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(kybes.runtime_of(kybes.Handler("function", "x", "y", d, None, None)), (None, None))


class CoverageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name) / "repo"
        shutil.copytree(FIXTURE, self.d)
        self.cfg = rules.normalize_config({"infra_root": "infra", "project": "acme",
                                           "kybes": {"root": ".", "openapi": "schemas/openapi.yaml"}})

    def tearDown(self):
        self.tmp.cleanup()

    def write_backend(self, handlers=COMPLETE_HANDLERS, jobs=COMPLETE_JOBS, env="dev"):
        stack = self.d / "infra" / "envs" / env / "backend"
        stack.mkdir(parents=True, exist_ok=True)
        if handlers is not None:
            (stack / "handlers.auto.tfvars").write_text(handlers, encoding="utf-8")
        if jobs is not None:
            (stack / "jobs.auto.tfvars").write_text(jobs, encoding="utf-8")

    def coverage(self, cfg=None):
        return [f for f in rules.check_project(self.d, cfg or self.cfg) if f.rule == "api-coverage"]

    def test_coverage_complete_ok(self):
        self.write_backend()
        self.write_backend(env="prod")
        self.assertEqual(self.coverage(), [])

    def test_coverage_missing_handler_blocks(self):
        handlers = COMPLETE_HANDLERS.replace('  "POST /v1/ordini"                  = "ordini/functions/crea-ordine"\n',
                                             "")
        self.write_backend(handlers=handlers)
        out = self.coverage()
        self.assertEqual(len(out), 1, [f.format() for f in out])
        f = out[0]
        self.assertEqual((f.severity, f.path), ("block", "schemas/openapi.yaml"))
        self.assertIn("POST /v1/ordini", f.message)
        lines = (self.d / "schemas" / "openapi.yaml").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[f.line - 1].strip(), "post:")

    def test_coverage_mapped_handler_missing_in_services(self):
        self.write_backend()
        shutil.rmtree(self.d / "services" / "ordini" / "functions" / "crea-ordine")
        out = self.coverage()
        self.assertTrue(any("ordini/functions/crea-ordine" in f.message and f.path == "schemas/openapi.yaml"
                            for f in out), [f.format() for f in out])

    def test_coverage_handler_and_job_without_infra(self):
        handlers = COMPLETE_HANDLERS.replace(
            '  "magazzino/ms/giacenze"         = { kind = "ms", runtime = "nodejs22.x", handler = "src/server.handler" }\n',
            "")
        self.write_backend(handlers=handlers, jobs='jobs = {}\n')
        out = self.coverage()
        paths = sorted((f.path, f.resource) for f in out)
        self.assertEqual(paths, [("infra/envs/dev/backend/handlers.auto.tfvars", "magazzino/ms/giacenze"),
                                 ("infra/envs/dev/backend/jobs.auto.tfvars", "sync-giacenze")])

    def test_coverage_missing_tfvars_and_bad_openapi_fail_closed(self):
        self.write_backend(handlers=None)
        out = self.coverage()
        self.assertEqual([f.path for f in out], ["infra/envs/dev/backend/handlers.auto.tfvars"])
        (self.d / "schemas" / "openapi.yaml").write_text("paths:\n  /x: &a {}\n", encoding="utf-8")
        out = self.coverage()
        self.assertEqual([(f.path, f.severity) for f in out], [("schemas/openapi.yaml", "block")])

    def test_coverage_inactive_without_kybes_or_backend(self):
        self.assertEqual(self.coverage(), [])  # nessuno stack backend: niente da confrontare
        self.write_backend(handlers="handlers = {}\nroutes = {}\n")
        self.assertEqual(self.coverage(rules.normalize_config({"infra_root": "infra", "project": "acme"})), [])
        self.assertNotEqual(self.coverage(), [])
        off = rules.normalize_config({"infra_root": "infra", "project": "acme", "kybes": {"root": "."},
                                      "rules": {"api-coverage": "off"}})
        self.assertEqual(self.coverage(off), [])


if __name__ == "__main__":
    unittest.main()
