"""Strumenti esterni dello stop gate e della CI: fmt, init/validate per stack, tflint, scanner (Checkov o Trivy).

Uno strumento mancante è un avviso (con il comando per installarlo) e non blocca; con strict=True (CI) è un errore.
Solo libreria standard.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import rules
import tools

TIMEOUT_S = 600


@dataclass
class Step:
    name: str
    argv: List[str]  # argv[0] è il nome logico dello strumento, risolto da _resolve al momento dell'esecuzione
    cwd: Path
    required: bool = True
    # analizza (stdout, exit code) e restituisce gli errori; None = solo exit code
    parse: Optional[Callable[[str, int], List[str]]] = field(default=None, compare=False, repr=False)


def _resolve(proj: Path, name: str) -> Optional[str]:
    """Percorso dell'eseguibile: .kynfra/bin, poi .kynfra/venv/bin, poi PATH (vedi tools.resolve_binary)."""
    return tools.resolve_binary(proj, name)


def _infra_root(proj: Path, cfg: dict) -> Path:
    root = cfg.get("infra_root", ".")
    return proj if root in ("", ".") else proj / root


def _stack_dirs(root: Path) -> List[Path]:
    """envs/<env>/<stack>/ (anche envs/shared/<stack>/) e bootstrap/ che contengono file .tf."""
    out: List[Path] = []
    envs = root / "envs"
    if envs.is_dir():
        for env in sorted(p for p in envs.iterdir() if p.is_dir()):
            out.extend(s for s in sorted(p for p in env.iterdir() if p.is_dir()) if any(s.glob("*.tf")))
    boot = root / "bootstrap"
    if boot.is_dir() and any(boot.glob("*.tf")):
        out.append(boot)
    return out


def _has_tf(root: Path) -> bool:
    if not root.is_dir():
        return False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".terraform", ".git", "node_modules")]
        if any(f.endswith(".tf") for f in filenames):
            return True
    return False


def external_steps(proj: Path, cfg: dict) -> List[Step]:
    root = _infra_root(proj, cfg)
    if not _has_tf(root):
        return []
    tf = "tofu" if cfg.get("iac") == "opentofu" else "terraform"
    steps = [Step("fmt", [tf, "fmt", "-check", "-recursive", "-no-color"], root, True)]
    for stack in _stack_dirs(root):
        label = stack.relative_to(root).as_posix()
        steps.append(Step(f"init {label}", [tf, "init", "-backend=false", "-input=false", "-no-color"], stack, True))
        steps.append(Step(f"validate {label}", [tf, "validate", "-no-color"], stack, True))
    tflint_cfg = root / ".tflint.hcl"
    if tflint_cfg.is_file():
        steps.append(Step("tflint", ["tflint", "--recursive", "--config", str(tflint_cfg.resolve())], root, True))
    # se manca .tflint.hcl lo segnala run_external (avviso: rilancia l'installer)
    if cfg.get("scanner") == "trivy":
        # nessuna esclusione per Trivy: il flag per ID di controllo non è stabile tra le versioni
        steps.append(Step("trivy", ["trivy", "config", "--exit-code", "1", str(root.resolve())], root, True))
    else:
        # niente --skip-check: la baseline del kit è per id, percorso e ambiente e si applica sull'output JSON
        argv = ["checkov", "-d", str(root.resolve()), "--framework", "terraform", "--quiet", "--compact",
                "-o", "json"]
        baseline = rules.scanner_baseline(cfg)
        steps.append(Step("checkov", argv, root, True,
                          parse=lambda out, rc: checkov_errors(out, rc, root.resolve(), baseline)))
    return steps


def _checkov_reports(data) -> Optional[List[dict]]:
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        return None
    return data


def checkov_errors(out: str, rc: int, root: Path, baseline: List[dict]) -> List[str]:
    """Errori dall'output JSON di Checkov: un errore per controllo fallito non escluso dalla baseline del kit
    (rules.baseline_allows), con id, risorsa e file:riga relativi a infra_root. Output non JSON con exit code diverso
    da 0: l'output stesso è l'errore."""
    try:
        reports = _checkov_reports(json.loads(out)) if out.strip() else []
    except ValueError:
        reports = None
    if reports is None:
        return [] if rc == 0 else [f"checkov (exit {rc}):\n{out.strip()[-3000:]}"]
    failed: List[str] = []
    seen_failures = 0
    for rep in reports:
        results = rep.get("results") if isinstance(rep.get("results"), dict) else {}
        for fc in results.get("failed_checks") or []:
            if not isinstance(fc, dict):
                continue
            seen_failures += 1
            path = str(fc.get("file_path") or fc.get("repo_file_path") or "")
            p = Path(path)
            if p.is_absolute():
                try:
                    path = p.resolve().relative_to(root).as_posix()
                except (ValueError, OSError):
                    path = path.lstrip("/")
            irel = path.lstrip("/")
            cid = str(fc.get("check_id") or "")
            if rules.baseline_allows(baseline, cid, irel):
                continue
            lines = fc.get("file_line_range") or [0]
            line = lines[0] if isinstance(lines, list) and lines else 0
            failed.append(f"- {cid} {fc.get('resource', '')} {irel}:{line} — {fc.get('check_name', '')}")
    if failed:
        return [f"checkov ({len(failed)} controlli falliti, fuori dalla baseline del kit):\n" + "\n".join(failed)]
    if rc != 0 and seen_failures == 0:
        return [f"checkov (exit {rc}) senza controlli falliti nell'output:\n{out.strip()[-3000:]}"]
    return []


def _install_hint(tool: str) -> str:
    return f"installa con /kynfra:kynfra-tools (tools.py install {tool})"


def run_external(steps: List[Step], strict: bool, proj: Path,
                 cfg: Optional[dict] = None, tools_proj: Optional[Path] = None) -> Tuple[List[str], List[str]]:
    """Esegue i passi; restituisce (errori, avvisi). I binari (.kynfra/bin, venv, verificati sul registro) e i plugin
    di TFLint si cercano in `tools_proj` (default: `proj`, il progetto stesso); con `cfg` controlla anche .tflint.hcl
    (errore in strict, avviso altrimenti)."""
    tools_proj = tools_proj or proj
    errors: List[str] = []
    warnings: List[str] = []
    missing: set = set()
    failed_init: set = set()
    if cfg is not None and not (_infra_root(proj, cfg) / ".tflint.hcl").is_file() and _has_tf(_infra_root(proj, cfg)):
        (errors if strict else warnings).append(
            "tflint: .tflint.hcl non trovato in infra_root: rilancia l'installer per generarlo")
    with tempfile.TemporaryDirectory(prefix="kynfra-tfdata-") as tmp:
        data_dirs: Dict[Path, str] = {}
        for step in steps:
            tool = step.argv[0]
            if tool in missing:
                continue
            exe = _resolve(tools_proj, tool)
            if exe is None:
                missing.add(tool)
                msg = f"{tool} non installato: {_install_hint(tool)}"
                (errors if strict and step.required else warnings).append(msg)
                continue
            if step.name.startswith("validate") and step.cwd in failed_init:
                continue
            env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0")
            if tool == "tflint":
                env["TFLINT_PLUGIN_DIR"] = str(tools_proj / ".kynfra/tflint.d/plugins")
            if step.name.startswith(("init", "validate")):
                if step.cwd not in data_dirs:
                    data_dirs[step.cwd] = tempfile.mkdtemp(dir=tmp)
                env["TF_DATA_DIR"] = data_dirs[step.cwd]
            try:
                r = subprocess.run([exe, *step.argv[1:]], cwd=str(step.cwd), env=env, capture_output=True,
                                   text=True, timeout=TIMEOUT_S)
            except subprocess.TimeoutExpired:
                errors.append(f"{step.name}: oltre {TIMEOUT_S}s")
                continue
            except OSError as e:
                errors.append(f"{step.name}: impossibile eseguire {exe}: {e}")
                continue
            if step.parse is not None:
                errors.extend(step.parse(r.stdout, r.returncode))
            elif r.returncode != 0:
                if step.name.startswith("init"):
                    failed_init.add(step.cwd)
                out = (r.stdout + r.stderr).strip()[-3000:]
                errors.append(f"{step.name} (exit {r.returncode}):\n{out}")
    return errors, warnings
