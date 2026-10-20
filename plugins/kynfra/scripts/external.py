"""Strumenti esterni dello stop gate e della CI: fmt, init/validate per stack, tflint, scanner (Checkov o Trivy).

Uno strumento mancante è un avviso (con il comando per installarlo) e non blocca; con strict=True (CI) è un errore.
Solo libreria standard.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import rules

TIMEOUT_S = 600


@dataclass
class Step:
    name: str
    argv: List[str]  # argv[0] è il nome logico dello strumento, risolto da _resolve al momento dell'esecuzione
    cwd: Path
    required: bool = True


def _resolve(proj: Path, name: str) -> Optional[str]:
    """Percorso dell'eseguibile: .kynfra/bin, poi .kynfra/venv/bin, poi PATH. (Task 11: tools.resolve_binary.)"""
    for sub in (".kynfra/bin", ".kynfra/venv/bin"):
        cand = proj / sub / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which(name)


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
        steps.append(Step("tflint", ["tflint", "--recursive", "--config", str(tflint_cfg.resolve()),
                                     "--chdir", str(root.resolve())], root, True))
    # se manca .tflint.hcl lo segnala run_external (avviso: rilancia l'installer)
    if cfg.get("scanner") == "trivy":
        # nessuna esclusione per Trivy: il flag per ID di controllo non è stabile tra le versioni
        steps.append(Step("trivy", ["trivy", "config", "--exit-code", "1", str(root.resolve())], root, True))
    else:
        argv = ["checkov", "-d", str(root.resolve()), "--framework", "terraform", "--quiet", "--compact"]
        skips = rules.scanner_skips(cfg, None)
        if skips:
            argv += ["--skip-check", ",".join(skips)]
        steps.append(Step("checkov", argv, root, True))
    return steps


def _install_hint(tool: str) -> str:
    return f"installa con /kynfra:tools (tools.py install {tool})"


def run_external(steps: List[Step], strict: bool, proj: Optional[Path] = None,
                 cfg: Optional[dict] = None) -> Tuple[List[str], List[str]]:
    """Esegue i passi; restituisce (errori, avvisi). `proj` serve a risolvere i binari in .kynfra/bin e venv."""
    errors: List[str] = []
    warnings: List[str] = []
    missing: set = set()
    failed_init: set = set()
    if cfg is not None and proj is not None and not (_infra_root(proj, cfg) / ".tflint.hcl").is_file() \
            and _has_tf(_infra_root(proj, cfg)):
        warnings.append("tflint: .tflint.hcl non trovato in infra_root: rilancia l'installer per generarlo")
    with tempfile.TemporaryDirectory(prefix="kynfra-tfdata-") as tmp:
        data_dirs: Dict[Path, str] = {}
        for step in steps:
            tool = step.argv[0]
            if tool in missing:
                continue
            base = proj if proj is not None else step.cwd
            exe = _resolve(base, tool)
            if exe is None:
                missing.add(tool)
                msg = f"{tool} non installato: {_install_hint(tool)}"
                (errors if strict and step.required else warnings).append(msg)
                continue
            if step.name.startswith("validate") and step.cwd in failed_init:
                continue
            env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0")
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
            if r.returncode != 0:
                if step.name.startswith("init"):
                    failed_init.add(step.cwd)
                out = (r.stdout + r.stderr).strip()[-3000:]
                errors.append(f"{step.name} (exit {r.returncode}):\n{out}")
    return errors, warnings
