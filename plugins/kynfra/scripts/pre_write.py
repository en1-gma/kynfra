#!/usr/bin/env python3
"""PreToolUse su Write/Edit/MultiEdit/NotebookEdit (Claude Code) e apply_patch (Codex): nega le scritture che violano regole bloccanti.

Le regole valutano il file come sarà DOPO la modifica (non solo il frammento scritto): togliere `encrypt = true` da un
backend con un Edit viene visto. Le violazioni già presenti prima della modifica non bloccano l'edit (le segnala lo
stop gate).
"""
from __future__ import annotations

import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import List, Optional

import hook_common as hc
import rules


def _key(f: rules.Finding, text: str) -> tuple:
    lines = text.splitlines()
    src = lines[f.line - 1].strip() if 0 < f.line <= len(lines) else ""
    return f.rule, src


def new_findings(rel: str, op: hc.FileOp, cfg: dict) -> List[rules.Finding]:
    if op.after is None:
        out: List[rules.Finding] = []
        for frag in op.fragments:
            out += rules.check_content(rel, frag, cfg)
        return out
    after = rules.check_content(rel, op.after, cfg)
    if not op.before:
        return after
    # solo ciò che la modifica introduce: stessa regola sulla stessa riga di codice = già presente
    seen = Counter(_key(f, op.before) for f in rules.check_content(rel, op.before, cfg))
    out = []
    for f in after:
        k = _key(f, op.after)
        if seen[k] > 0:
            seen[k] -= 1
        else:
            out.append(f)
    return out


def _lexical_rel(path: Path, proj: Path) -> Optional[str]:
    """Percorso relativo al progetto SENZA seguire i link simbolici dopo la radice del progetto (che può essere
    raggiunta da un percorso con link, es. /tmp → /private/tmp su macOS)."""
    p = Path(os.path.normpath(str(path)))
    root = proj.resolve()
    for anc in (p, *p.parents):
        try:
            if anc.resolve() == root:
                rel = p.relative_to(anc).as_posix()
                return "" if rel == "." else rel
        except OSError:
            continue
    return None


def _through_symlink(rel: str, proj: Path) -> bool:
    cur = proj.resolve()
    for part in [x for x in rel.split("/") if x]:
        cur = cur / part
        if cur.is_symlink():
            return True
    return False


def _symlink_findings(path: Path, proj: Path, cfg: dict, rel: Optional[str]) -> List[rules.Finding]:
    """Scrittura attraverso un link simbolico (file o cartella) in infra_root o in un percorso protetto: le regole
    vedrebbero il file di destinazione, Terraform quello del link."""
    lex = _lexical_rel(path, proj)
    if lex is None or not _through_symlink(lex, proj):
        return []
    sensitive = rules.infra_rel(lex, cfg) is not None or bool(rules.protected_reason(lex, cfg)) \
        or (rel is not None and (rules.infra_rel(rel, cfg) is not None or bool(rules.protected_reason(rel, cfg))))
    if not sensitive:
        return []
    return [rules.Finding("folder-layout", "block", lex, 0,
                          "scrittura attraverso un link simbolico sotto infra_root o in un file protetto: i controlli "
                          "non vedrebbero il file che Terraform legge; usa il percorso vero (niente link)")]


def _check_op(event: dict, op: hc.FileOp, proj, cfg: dict) -> List[rules.Finding]:
    hc.record_baseline(event, proj)
    path = hc._abs(op.path, event.get("cwd"))
    rel = rules.rel_to_project(str(path), proj)
    links = _symlink_findings(path, proj, cfg, rel)
    if rel is None:
        return links
    out = links + rules.check_protected(rel, cfg)
    if op.kind != "write":
        return out
    return out + rules.check_layout(rel, cfg) + new_findings(rel, op, cfg)


def _guarded(op: hc.FileOp, event: dict, proj, cfg: dict) -> bool:
    """Il file è soggetto alle regole (sotto infra_root, o protetto)? Nel dubbio sì."""
    try:
        rel = rules.rel_to_project(str(hc._abs(op.path, event.get("cwd"))), proj)
        return rel is not None and (rules.infra_rel(rel, cfg) is not None or bool(rules.protected_reason(rel, cfg)))
    except Exception:
        return True


def _findings(event: dict) -> List[rules.Finding]:
    findings = []
    for op in hc.file_ops(event):
        proj = rules.project_for_file(op.path, event.get("cwd"))
        cfg = rules.load_config(proj)
        if cfg is None:
            continue  # file fuori da un progetto kynfra: nessun controllo
        try:
            findings += _check_op(event, op, proj, cfg)
        except Exception as e:  # una guardia che si rompe non deve lasciar passare la scrittura (come bash_guard)
            if not _guarded(op, event, proj, cfg):
                continue
            findings.append(rules.Finding("internal-error", "block", op.path, 0,
                                          f"errore interno dei controlli ({type(e).__name__}): scrittura non "
                                          "verificabile, segnala il problema"))
    return findings


def _deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))


def main() -> int:
    event = hc.read_event()
    hc.debug_dump(event, "pre")
    try:
        findings = _findings(event)
    except Exception as e:  # fail closed dentro un progetto kynfra (config illeggibile, errore imprevisto)
        if hc.in_kynfra_project(event, [op.path for op in _safe_ops(event)]):
            _deny(f"Scrittura rifiutata: errore interno dei controlli di kynfra ({type(e).__name__}), scrittura non "
                  "verificabile. Segnala il problema; controlla che .kynfra/config.json sia valido.")
        return 0
    blocking = [f for f in findings if f.severity == "block"]
    if not blocking:
        return 0
    _deny("Scrittura rifiutata dalle regole di infrastruttura del progetto (kynfra):\n"
          + "\n".join(f.format() for f in blocking)
          + "\nCorreggi l'approccio secondo la skill kynfra-architecture invece di aggirare il controllo.")
    return 0


def _safe_ops(event: dict) -> List[hc.FileOp]:
    try:
        return hc.file_ops(event)
    except Exception:
        return []


if __name__ == "__main__":
    sys.exit(main())
