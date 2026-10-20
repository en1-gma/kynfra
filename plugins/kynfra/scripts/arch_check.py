#!/usr/bin/env python3
"""Controllo completo del progetto: regole di kynfra su tutto infra_root e, con --external, gli strumenti esterni.

Uso: python3 arch_check.py [PROGETTO] [--strict] [--external]
Esce con 1 se c'è un finding bloccante (con --strict anche un avviso), oppure un errore degli strumenti esterni
(con --strict anche uno strumento mancante).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import external  # noqa: E402
import rules  # noqa: E402


def run(proj: Path, cfg: dict) -> List[rules.Finding]:
    """Findings dell'intero progetto, compresa la soglia bloccante di literal-reuse (modalità stop gate)."""
    return rules.check_project(proj, cfg, stop_gate=True)


def literal_reuse_stats(proj: Path, cfg: dict) -> Tuple[int, int]:
    """(occorrenze di letterali di dominio, occorrenze duplicate) con le stesse regole di rules.literal_reuse."""
    import rules_common

    project = cfg.get("project") or ""
    occ: dict = {}
    for path, _, _, blocks in rules._parse_project(proj, cfg):
        irel = rules.infra_rel(path, cfg)
        if irel is None or irel.lower().endswith(rules_common.TFVARS_EXT) or \
                irel.split("/")[0] not in ("modules", "envs"):
            continue
        for block in blocks:
            for b in rules_common._walk_blocks([block]):
                for attr in b.attrs.values():
                    for key, value in rules._domain_literals(attr):
                        dv = rules._domain_value(key, value, project)
                        if dv is not None:
                            occ.setdefault(dv, []).append(path)
    total = sum(len(v) for v in occ.values())
    dup = sum(len(v) - 1 for v in occ.values() if len(set(v)) >= 2)
    return total, dup


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("project", nargs="?", default=".")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--external", action="store_true")
    a = ap.parse_args()
    proj = Path(a.project).resolve()
    cfg = rules.load_config(proj)
    if cfg is None:
        print(f"kynfra: {rules.CONFIG_REL} non trovato in {proj}: nessun controllo")
        return 0
    findings = run(proj, cfg)
    for sevname, title in (("block", "Violazioni bloccanti"), ("warn", "Avvisi")):
        sel = [f for f in findings if f.severity == sevname]
        if sel:
            print(f"{title} ({len(sel)}):")
            print("\n".join(f.format() for f in sel))
    total, dup = literal_reuse_stats(proj, cfg)
    ratio = dup / total if total else 0.0
    limit = float(cfg["literal_reuse"].get("max_duplicate_ratio", 0.10))
    print(f"kynfra: riuso letterali — {dup} duplicati su {total} ({ratio:.1%}, soglia {limit:.0%})")
    if not findings:
        print("kynfra: nessuna violazione")
    failing = any(f.severity == "block" or (a.strict and f.severity == "warn") for f in findings)
    if a.external:
        errors, warnings = external.run_external(external.external_steps(proj, cfg), a.strict, proj, cfg)
        for w in warnings:
            print(f"Avviso strumenti esterni: {w}")
        if errors:
            print(f"Errori strumenti esterni ({len(errors)}):")
            print("\n".join(errors))
            failing = True
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
