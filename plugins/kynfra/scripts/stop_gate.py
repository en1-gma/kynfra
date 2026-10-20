#!/usr/bin/env python3
"""Stop / SubagentStop (Claude Code e Codex): impedisce di chiudere il lavoro finché i controlli non passano.

Esegue le regole di kynfra sull'intero progetto, gli strumenti esterni (fmt, validate, tflint, scanner: se mancano
avvisa e non blocca) e i comandi in stop_gate.commands.

- Anti-loop: blocca fino a `max_blocks` volte di fila nella stessa catena di stop; poi lascia chiudere con un avviso
  esplicito. `stop_hook_active` (Claude sta continuando per un nostro blocco) NON sblocca il gate: serve solo a capire
  se la catena è nuova, e in quel caso il contatore riparte da zero.
- "Ci sono modifiche" non è solo `git status`: conta anche HEAD diverso da quello di inizio sessione e i commit non
  ancora pubblicati, così un commit non spegne il gate.
- Monorepo: se il cwd non è un progetto kynfra, controlla i progetti kynfra sotto il cwd.
- Fail closed: un errore inatteso nei controlli (o nel gate stesso) blocca come un controllo fallito, con lo stesso
  anti-loop; un gate rotto non deve lasciar chiudere in silenzio.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

import arch_check
import external
import hook_common as hc
import rules

TIMEOUT_S = 600


def has_changes(event: dict, proj: Path) -> bool:
    status = hc._git(proj, "status", "--porcelain")
    if status is None:
        return True  # non è un repository git (o git non risponde): controlla sempre
    if status:
        return True
    head = hc._git(proj, "rev-parse", "HEAD")
    base_file = hc.baseline_path(event, proj)
    if base_file.is_file():
        try:
            return base_file.read_text().strip() != head
        except OSError:
            return True
    # nessuna baseline (prima azione della sessione): commit locali non presenti su nessun remote
    unpublished = hc._git(proj, "rev-list", "--count", "HEAD", "--not", "--remotes")
    return unpublished is None or unpublished != "0"


def counter_path(event: dict, proj: Path) -> Path:
    kind = "sub" if event.get("hook_event_name") == "SubagentStop" else "main"
    tag = "".join(c if c.isalnum() else "_" for c in str(proj))[-80:]
    return Path(tempfile.gettempdir()) / f"kynfra-stop-{hc._session_key(event)}-{kind}-{tag}.count"


def error_counter_path(event: dict) -> Path:
    """Contatore anti-loop per gli errori inattesi fuori da un singolo progetto (prima di sapere quale)."""
    cwd = str(Path(event.get("cwd") or ".").resolve())
    return counter_path(event, Path(cwd + "#errore"))


def _internal_error(e: BaseException) -> str:
    return (f"errore interno dei controlli di kynfra ({type(e).__name__}: {e}): il progetto non è verificabile; "
            "segnala il problema e verifica i file a mano")


def _decide(event: dict, cnt_file: Path, max_blocks: int, failures: List[str], notes: str, where: str) -> dict:
    """Blocco con anti-loop: al tentativo max_blocks+1 della stessa catena lascia chiudere con un avviso."""
    count = 0
    if event.get("stop_hook_active") is True:
        try:
            count = int(cnt_file.read_text())
        except Exception:
            count = 0
    count += 1
    if count > max_blocks:
        cnt_file.unlink(missing_ok=True)
        return {"systemMessage": f"kynfra{where}: controlli ancora falliti dopo {max_blocks} tentativi; "
                                 "chiusura consentita, ma il lavoro NON è conforme."}
    cnt_file.write_text(str(count))
    return {"decision": "block",
            "reason": (f"I controlli dell'infrastruttura (kynfra){where} non passano. Correggi prima di chiudere "
                       f"(tentativo {count}/{max_blocks}):\n\n" + "\n\n".join(failures)
                       + (f"\n\n{notes}" if notes else ""))}


def run_checks(proj: Path, cfg: dict) -> Tuple[List[str], List[str]]:
    """(fallimenti, avvisi)."""
    failures: List[str] = []
    blocking = [f for f in arch_check.run(proj, cfg) if f.severity == "block"]
    if blocking:
        failures.append("arch_check:\n" + "\n".join(f.format() for f in blocking[:40]))
    errors, warnings = external.run_external(external.external_steps(proj, cfg), False, proj, cfg)
    failures.extend(errors)
    for cmd in (cfg.get("stop_gate") or {}).get("commands") or []:
        try:
            r = subprocess.run(cmd, shell=True, cwd=str(proj), capture_output=True, text=True, timeout=TIMEOUT_S)
        except subprocess.TimeoutExpired:
            failures.append(f"{cmd}: oltre {TIMEOUT_S}s")
            continue
        if r.returncode != 0:
            failures.append(f"{cmd} (exit {r.returncode}):\n" + (r.stdout + r.stderr).strip()[-3000:])
    return failures, warnings


def gate(event: dict, proj: Path, cfg: dict) -> Optional[dict]:
    gate_cfg = cfg.get("stop_gate") or {}
    if not gate_cfg.get("enabled", True):
        return None
    cnt_file = counter_path(event, proj)
    if gate_cfg.get("only_if_changes", True) and not has_changes(event, proj):
        cnt_file.unlink(missing_ok=True)
        return None
    max_blocks = int(gate_cfg.get("max_blocks", 3))
    try:
        failures, warnings = run_checks(proj, cfg)
    except Exception as e:  # fail closed
        failures, warnings = [_internal_error(e)], []
    notes = "\n".join(f"kynfra ({proj.name}): {w}" for w in warnings)
    if not failures:
        cnt_file.unlink(missing_ok=True)
        return {"systemMessage": notes} if notes else None
    return _decide(event, cnt_file, max_blocks, failures, notes, f" in {proj.name}" if proj.name else "")


def main() -> int:
    event = hc.read_event()
    try:
        return _main(event)
    except Exception as e:  # fail closed: un errore del gate blocca, con l'anti-loop (max_blocks di default)
        try:
            out = _decide(event, error_counter_path(event), 3, [_internal_error(e)], "", "")
        except Exception:
            out = {"decision": "block", "reason": _internal_error(e)}
        print(json.dumps(out, ensure_ascii=False))
        return 0


def _main(event: dict) -> int:
    hc.debug_dump(event, "stop")
    cwd = Path(event.get("cwd") or ".").resolve()
    proj = rules.find_project_dir(str(cwd))
    projects = [proj] if rules.load_config(proj) is not None else rules.discover_projects(cwd)
    blocks, notes = [], []
    for p in projects:
        cfg = rules.load_config(p)
        if cfg is None:
            continue
        out = gate(event, p, cfg)
        if not out:
            continue
        if out.get("decision") == "block":
            blocks.append(out["reason"])
        else:
            notes.append(out["systemMessage"])
    if blocks:
        print(json.dumps({"decision": "block", "reason": "\n\n".join(blocks)}, ensure_ascii=False))
    elif notes:
        print(json.dumps({"systemMessage": "\n".join(notes)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
