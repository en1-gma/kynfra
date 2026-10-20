"""Harness dei pattern: ogni pattern di templates/<provider>/patterns.json si genera in una cartella vuota con la config
di riferimento (ambienti dev e prod, più i pattern richiesti) e deve passare arch_check in modalità strict con zero
finding, avvisi compresi. Se terraform/tofu, tflint o checkov sono risolvibili (tools.resolve_binary) esegue anche gli
strumenti esterni; con KYNFRA_REQUIRE_TOOLS=1 (CI) sono obbligatori. KYNFRA_PATTERNS="p1 p2" limita i pattern.
KYNFRA_TOOLS_PROJECT=<dir> usa i binari verificati sul registro di <dir>/.kynfra (e i suoi plugin di TFLint) invece
di quelli del progetto temporaneo, es. gli strumenti installati con tools.py nel repository del kit.
I pattern `single_env` si generano un ambiente per comando; `example` può essere un dizionario {ambiente: valore}.
VARIANTS aggiunge combinazioni di input da verificare allo stesso modo (es. spa con zona esistente e /api/*).
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "plugins" / "kynfra"
sys.path.insert(0, str(PLUGIN / "scripts"))

import arch_check  # noqa: E402
import external  # noqa: E402
import generate  # noqa: E402
import rules  # noqa: E402
import tools  # noqa: E402

PROVIDERS = ("aws",)
ENVS = ["dev", "prod"]
REFERENCE_CONFIG = {
    "iac": "terraform",
    "providers": ["aws"],
    "infra_root": "infra",
    "project": "acme",
    "region": "eu-south-1",
    "accounts": {"main": {"id": "123456789012"}},
    "environments": {"dev": {"account": "main"}, "staging": {"account": "main"}, "prod": {"account": "main"}},
    "tags": {"Owner": "platform", "CostCenter": "cc-001"},
    "scanner": "checkov",
    "rules": {},
    "exceptions": [],
}


def patterns(provider: str):
    data = json.loads((PLUGIN / "templates" / provider / "patterns.json").read_text(encoding="utf-8"))
    names = sorted(k for k in data if not k.startswith("_"))
    wanted = [p for p in re.split(r"[\s,]+", os.environ.get("KYNFRA_PATTERNS", "")) if p]
    return [n for n in names if not wanted or n in wanted]


def with_requires(provider: str, pattern: str, seen=None) -> list:
    """Il pattern preceduto dai suoi requires (in profondità, senza doppioni)."""
    seen = [] if seen is None else seen
    for req in generate.load_pattern(provider, pattern)["requires"]:
        if req not in seen:
            with_requires(provider, req, seen)
    if pattern not in seen:
        seen.append(pattern)
    return seen


# combinazioni di input in più per pattern: ognuna diventa un test con gli stessi controlli
VARIANTS = {
    "spa": [{"hosted_zone": "existing:Z0123456789ABCDEFGHIJ", "api_origin": "backend"}],
    # replica in un'altra regione e segreti con lettori e Lambda di rotazione (la chiave "_tfvars" sostituisce testo
    # nei terraform.tfvars generati: struttura che il generatore non sa passare)
    "ecr": [{"repositories": "api,worker,jobs-nightly", "keep_last": "50",
             "pull_principals": "arn:aws:iam::123456789012:role/acme-eks-node,arn:aws:iam::123456789012:role/acme-app"}],
    "secrets": [{"replica_region": "eu-west-1", "_tfvars": [
        ('    description = "Credenziali del database dell\'applicazione"\n    readers     = []\n    # rotation_lambda_arn',
         '    description         = "Credenziali del database dell\'applicazione"\n'
         '    readers             = ["arn:aws:iam::123456789012:role/acme-dev-app"]\n    rotation_lambda_arn'),
    ]}],
}


def sample_values(provider: str, pattern: str, env: str = "") -> dict:
    """Valori degli input richiesti senza default: il campo `example` di patterns.json (per ambiente se è un
    dizionario)."""
    out = {}
    for name, spec in generate.load_pattern(provider, pattern)["inputs"].items():
        if spec.get("required", True) and spec.get("default") is None:
            if "example" not in spec:
                raise AssertionError(f"input '{name}' del pattern '{pattern}' senza example in patterns.json")
            ex = spec["example"]
            out[name] = str(ex[env] if isinstance(ex, dict) else ex)
    return out


def generate_pattern(proj: Path, cfg: dict, provider: str, pattern: str, extra: dict = None) -> list:
    """Genera il pattern per ENVS (un comando per ambiente se single_env); ritorna i risultati di generate."""
    groups = [[e] for e in ENVS] if generate.load_pattern(provider, pattern).get("single_env") else [ENVS]
    return [generate.generate(proj, cfg, provider, pattern, envs,
                              {**sample_values(provider, pattern, envs[0]), **(extra or {})}) for envs in groups]


def make_project(base: Path) -> dict:
    (base / ".kynfra").mkdir(parents=True)
    (base / ".kynfra/config.json").write_text(json.dumps(REFERENCE_CONFIG), encoding="utf-8")
    cfg = rules.load_config(base)
    infra = base / cfg["infra_root"]
    infra.mkdir(parents=True, exist_ok=True)
    ruleset = json.loads((PLUGIN / "templates/versions.json").read_text())["tflint_ruleset_aws"]["version"]
    tflint = (PLUGIN / "templates/tflint.hcl").read_text().replace("__RULESET_AWS_VERSION__", ruleset)
    (infra / ".tflint.hcl").write_text(tflint, encoding="utf-8")
    return cfg


class PatternsTest(unittest.TestCase):
    maxDiff = None

    def check_pattern(self, provider: str, pattern: str, extra: dict = None):
        with tempfile.TemporaryDirectory(prefix=f"kynfra-{pattern}-") as d:
            proj = Path(d)
            cfg = make_project(proj)
            extra = dict(extra or {})
            edits = extra.pop("_tfvars", [])
            for p in with_requires(provider, pattern):
                for res in generate_pattern(proj, cfg, provider, p, extra if p == pattern else None):
                    self.assertTrue(res["created"], p)
                    self.assertEqual(res["missing_requires"], [], p)
            for path in proj.glob(f"**/envs/*/{pattern}/terraform.tfvars"):
                text = path.read_text(encoding="utf-8")
                for old, new in edits:
                    self.assertIn(old, text)
                    text = text.replace(old, new)
                path.write_text(text, encoding="utf-8")
            findings = arch_check.run(proj, cfg)
            self.assertEqual([f.format() for f in findings], [], f"pattern {pattern}: arch_check --strict")
            iac = "tofu" if cfg["iac"] == "opentofu" else "terraform"
            required = os.environ.get("KYNFRA_REQUIRE_TOOLS") == "1"
            tools_proj = Path(os.environ["KYNFRA_TOOLS_PROJECT"]) if os.environ.get("KYNFRA_TOOLS_PROJECT") else proj
            if not required and not any(tools.resolve_binary(tools_proj, n) for n in (iac, "tflint", "checkov")):
                return
            errors, _ = external.run_external(external.external_steps(proj, cfg), required, proj, cfg,
                                              tools_proj=tools_proj)
            self.assertEqual(errors, [], f"pattern {pattern}: strumenti esterni")


def _add_tests():
    for provider in PROVIDERS:
        for name in patterns(provider):
            def test(self, provider=provider, name=name):
                self.check_pattern(provider, name)
            setattr(PatternsTest, f"test_pattern_{provider}_{name.replace('-', '_')}", test)
            for i, extra in enumerate(VARIANTS.get(name, []), 1):
                def variant(self, provider=provider, name=name, extra=extra):
                    self.check_pattern(provider, name, extra)
                setattr(PatternsTest, f"test_pattern_{provider}_{name.replace('-', '_')}_variant_{i}", variant)


_add_tests()

if __name__ == "__main__":
    unittest.main()
