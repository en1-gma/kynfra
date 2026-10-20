"""Harness dei pattern: ogni pattern di templates/<provider>/patterns.json si genera in una cartella vuota con la config
di riferimento (ambienti dev e prod, più i pattern richiesti) e deve passare arch_check in modalità strict con zero
finding, avvisi compresi. Se terraform/tofu, tflint o checkov sono risolvibili (tools.resolve_binary) esegue anche gli
strumenti esterni; con KYNFRA_REQUIRE_TOOLS=1 (CI) sono obbligatori. KYNFRA_PATTERNS="p1 p2" limita i pattern.
Gli strumenti installati con tools.py nel repository del kit (.kynfra/, o KYNFRA_TOOLS_DIR) si riusano.
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
TOOL_LINKS = ("bin", "venv", "tflint.d", "tools.lock.json")


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


def sample_values(provider: str, pattern: str) -> dict:
    """Valori degli input richiesti senza default: il campo `example` di patterns.json."""
    out = {}
    for name, spec in generate.load_pattern(provider, pattern)["inputs"].items():
        if spec.get("required", True) and spec.get("default") is None:
            if "example" not in spec:
                raise AssertionError(f"input '{name}' del pattern '{pattern}' senza example in patterns.json")
            out[name] = str(spec["example"])
    return out


def make_project(base: Path) -> dict:
    (base / ".kynfra").mkdir(parents=True)
    (base / ".kynfra/config.json").write_text(json.dumps(REFERENCE_CONFIG), encoding="utf-8")
    tools_home = Path(os.environ.get("KYNFRA_TOOLS_DIR") or ROOT / ".kynfra")
    for name in TOOL_LINKS:
        if (tools_home / name).exists():
            os.symlink(tools_home / name, base / ".kynfra" / name)
    cfg = rules.load_config(base)
    infra = base / cfg["infra_root"]
    infra.mkdir(parents=True, exist_ok=True)
    ruleset = json.loads((PLUGIN / "templates/versions.json").read_text())["tflint_ruleset_aws"]["version"]
    tflint = (PLUGIN / "templates/tflint.hcl").read_text().replace("__RULESET_AWS_VERSION__", ruleset)
    (infra / ".tflint.hcl").write_text(tflint, encoding="utf-8")
    return cfg


class PatternsTest(unittest.TestCase):
    maxDiff = None

    def check_pattern(self, provider: str, pattern: str):
        with tempfile.TemporaryDirectory(prefix=f"kynfra-{pattern}-") as d:
            proj = Path(d)
            cfg = make_project(proj)
            for p in with_requires(provider, pattern):
                res = generate.generate(proj, cfg, provider, p, ENVS, sample_values(provider, p))
                self.assertTrue(res["created"], p)
                self.assertEqual(res["missing_requires"], [], p)
            findings = arch_check.run(proj, cfg)
            self.assertEqual([f.format() for f in findings], [], f"pattern {pattern}: arch_check --strict")
            iac = "tofu" if cfg["iac"] == "opentofu" else "terraform"
            required = os.environ.get("KYNFRA_REQUIRE_TOOLS") == "1"
            if not required and not any(tools.resolve_binary(proj, n) for n in (iac, "tflint", "checkov")):
                return
            errors, _ = external.run_external(external.external_steps(proj, cfg), required, proj, cfg)
            self.assertEqual(errors, [], f"pattern {pattern}: strumenti esterni")


def _add_tests():
    for provider in PROVIDERS:
        for name in patterns(provider):
            def test(self, provider=provider, name=name):
                self.check_pattern(provider, name)
            setattr(PatternsTest, f"test_pattern_{provider}_{name.replace('-', '_')}", test)


_add_tests()

if __name__ == "__main__":
    unittest.main()
