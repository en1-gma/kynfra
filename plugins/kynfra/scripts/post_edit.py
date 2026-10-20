#!/usr/bin/env python3
"""PostToolUse: rilegge i file appena scritti e restituisce all'agente gli avvisi (regole 'warn' e letterali ripetuti)."""
from __future__ import annotations

import json
import sys
from typing import List

import hook_common as hc
import rules

MAX_LINES = 15


def reuse_notes(proj, cfg: dict, rel: str) -> List[rules.Finding]:
    """Avvisi literal-reuse che riguardano il file appena scritto (analisi su tutti i file Terraform del progetto)."""
    import hcl

    files = []
    for frel, path in rules.iter_project_files(proj, cfg):
        if not frel.lower().endswith(rules.TF_EXT):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files.append((frel, hcl.parse(text, path.name.lower())))
    return [f for f in rules.literal_reuse(files, cfg) if f.path == rel and f.severity == "warn"]


def main() -> int:
    event = hc.read_event()
    hc.debug_dump(event, "post")
    findings: List[rules.Finding] = []
    for path in hc.written_files(event):
        proj = rules.project_for_file(path, event.get("cwd"))
        cfg = rules.load_config(proj)
        if cfg is None:
            continue
        rel = rules.rel_to_project(str(hc._abs(path, event.get("cwd"))), proj)
        if rel is None:
            continue
        p = proj / rel
        if not p.is_file():
            continue
        try:
            findings += [f for f in rules.check_content(rel, p.read_text(encoding="utf-8", errors="replace"), cfg)
                         if f.severity == "warn"]
            findings += reuse_notes(proj, cfg, rel)
        except Exception:
            continue  # il post-hook è solo informativo: non deve mai rompere la sessione
    if not findings:
        return 0
    lines = [f.format() for f in findings]
    ctx = "kynfra — avvisi da sistemare prima di chiudere il lavoro:\n" + "\n".join(lines[:MAX_LINES])
    if len(lines) > MAX_LINES:
        ctx += f"\n- … e altri {len(lines) - MAX_LINES} avvisi"
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": ctx}},
                     ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
