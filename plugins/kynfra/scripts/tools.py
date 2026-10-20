#!/usr/bin/env python3
"""Gestore degli strumenti esterni di kynfra: download approvato, verificato e tracciato, uno strumento alla volta.

Comandi: `tools.py status | plan <tool> | install <tool> --approved-by "<utente git>" | verify`.

Regole (spec 7.3.1):
- sorgenti solo https e solo host ufficiali in ALLOWED_HOSTS (anche dopo i redirect);
- verifica: SHA256 dell'archivio scaricato contro il file SHA256SUMS ufficiale scaricato via HTTPS dallo stesso host.
  Le FIRME GPG NON sono verificate nella v1: la fiducia poggia su HTTPS + host ufficiale + checksum;
- Checkov (kind "pypi"): virtualenv in .kynfra/venv e `pip install checkov==<versione>` da PyPI;
- installazione solo sotto .kynfra/bin e .kynfra/venv, mai globale, mai come root (niente sudo);
- .kynfra/tools.lock.json lo scrive solo questo script (chiavi ordinate, indent 2).
Solo libreria standard.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import platform
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
LOCK_REL = ".kynfra/tools.lock.json"
BIN_REL = ".kynfra/bin"
VENV_REL = ".kynfra/venv"
ALLOWED_HOSTS = frozenset({
    "releases.hashicorp.com", "github.com", "objects.githubusercontent.com", "pypi.org", "files.pythonhosted.org",
})
ALIASES = {"tofu": "opentofu", "tflint-ruleset-aws": "tflint_ruleset_aws"}
TRIVY_OS = {"darwin": "macOS", "linux": "Linux"}
TRIVY_ARCH = {"amd64": "64bit", "arm64": "ARM64"}
MAX_DOWNLOAD = 600 * 1024 * 1024
NO_VERSION_CHECK = {"tflint_ruleset_aws"}  # plugin di TFLint: non è eseguibile da solo


class ToolError(Exception):
    """Errore d'uso o di verifica: il messaggio è già per l'utente."""


# ------------------------------------------------------------------ catalogo

def _read_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def catalog() -> Dict[str, dict]:
    """tool -> {version, url_template, checksums_url, signature, archive, binary, kind}."""
    cat = _read_json(TEMPLATES / "tools-catalog.json")
    versions = _read_json(TEMPLATES / "versions.json")
    out: Dict[str, dict] = {}
    for name, entry in cat.items():
        if name.startswith("_"):
            continue
        out[name] = dict(entry, version=str(versions.get(name, {}).get("version", "")))
    return out


def canonical(tool: str) -> str:
    return ALIASES.get(tool, tool)


def _entry(tool: str) -> dict:
    cat = catalog()
    name = canonical(tool)
    if name not in cat:
        raise ToolError(f"strumento '{tool}' fuori catalogo (disponibili: {', '.join(sorted(cat))})")
    if not cat[name]["version"]:
        raise ToolError(f"versione di '{tool}' non definita in versions.json")
    return cat[name]


# ------------------------------------------------------------------ rete

def check_url(url: str) -> None:
    p = urllib.parse.urlparse(url)
    if p.scheme != "https":
        raise ToolError(f"URL non https rifiutato: {url}")
    if (p.hostname or "") not in ALLOWED_HOSTS:
        raise ToolError(f"host non ufficiale rifiutato: {p.hostname}")


class _AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def urllib_fetch(url: str) -> bytes:
    check_url(url)
    opener = urllib.request.build_opener(_AllowlistRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "kynfra-tools"})
    try:
        with opener.open(req, timeout=120) as r:
            data = r.read(MAX_DOWNLOAD + 1)
    except (urllib.error.URLError, OSError) as e:
        raise ToolError(f"download fallito ({url}): {e}")
    if len(data) > MAX_DOWNLOAD:
        raise ToolError(f"download troppo grande: {url}")
    return data


# ------------------------------------------------------------------ piattaforma

def detect_platform() -> tuple:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if sysname not in ("darwin", "linux") or arch is None:
        raise ToolError(f"piattaforma non supportata: {platform.system()} {platform.machine()} "
                        "(supportati: darwin/linux su amd64/arm64)")
    return sysname, arch


def _check_platform(os_: str, arch: str) -> None:
    if os_ not in ("darwin", "linux") or arch not in ("amd64", "arm64"):
        raise ToolError(f"piattaforma non supportata: {os_}/{arch} (supportati: darwin/linux su amd64/arm64)")


def _fill(template: str, e: dict, os_: str, arch: str) -> str:
    return template.format(version=e["version"], os=os_, arch=arch,
                           tos=TRIVY_OS.get(os_, os_), tarch=TRIVY_ARCH.get(arch, arch))


# ------------------------------------------------------------------ registro

def lock_path(proj: Path) -> Path:
    return proj / LOCK_REL


def read_lock(proj: Path) -> dict:
    try:
        data = _read_json(lock_path(proj))
    except (OSError, ValueError):
        return {"tools": {}}
    if not isinstance(data, dict) or not isinstance(data.get("tools"), dict):
        return {"tools": {}}
    return data


def _atomic_write(dest: Path, data: bytes, mode: int = 0o644) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(dest.parent), prefix=".tmp-kynfra-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_lock(proj: Path, lock: dict) -> None:
    text = json.dumps(lock, sort_keys=True, indent=2) + "\n"
    _atomic_write(lock_path(proj), text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ piano

def _binary_path(proj: Path, e: dict) -> Path:
    sub = f"{VENV_REL}/bin" if e["kind"] == "pypi" else BIN_REL
    return proj / sub / e["binary"]


def plan_install(proj: Path, tool: str, os_: str, arch: str) -> dict:
    """{tool, version, url, sha256_url, dest, approval_text}: ciò che l'utente approva per quel solo strumento."""
    _check_platform(os_, arch)
    e = _entry(tool)
    name = canonical(tool)
    dest = _binary_path(proj, e)
    if e["kind"] == "pypi":
        url = e["url_template"].format(version=e["version"])
        sha_url = None
        how = (f"virtualenv dedicato in {proj / VENV_REL}, `pip install {e['binary']}=={e['version']}` da PyPI "
               "(pip.pypa.io); l'hash della wheel è quello scelto da pip")
        sha_line = "SHA256 atteso: non pubblicato in anticipo (fonte PyPI, hash registrato dopo l'installazione)"
    else:
        url = _fill(e["url_template"], e, os_, arch)
        sha_url = _fill(e["checksums_url"], e, os_, arch)
        how = f"archivio {e['archive']}, estratto solo il file '{e['binary']}'"
        sha_line = (f"SHA256 atteso: letto da {sha_url} (file ufficiale via HTTPS) per "
                    f"{posixpath.basename(urllib.parse.urlparse(url).path)}")
    text = "\n".join([
        f"Installazione di {name} {e['version']}",
        f"  Sorgente ufficiale: {url}",
        f"  {sha_line}",
        f"  Destinazione: {dest}",
        f"  Modalità: {how}",
        "  Firme GPG: non verificate nella v1 (si verifica il checksum SHA256 via HTTPS dall'host ufficiale).",
        "  L'approvazione vale solo per questo strumento e questa versione.",
    ])
    return {"tool": name, "version": e["version"], "url": url, "sha256_url": sha_url, "dest": str(dest),
            "approval_text": text}


# ------------------------------------------------------------------ installazione

def _parse_sums(text: str, filename: str) -> Optional[str]:
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            return parts[0].lower()
    return None


def _safe_names(names: List[str]) -> None:
    for n in names:
        if n.startswith("/") or ".." in n.replace("\\", "/").split("/") or re.match(r"^[A-Za-z]:", n):
            raise ToolError(f"archivio rifiutato: voce non sicura '{n}'")


def _extract_binary(data: bytes, archive: str, binary: str) -> bytes:
    try:
        if archive == "zip":
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                _safe_names(z.namelist())
                for info in z.infolist():
                    if not info.is_dir() and posixpath.basename(info.filename) == binary:
                        return z.read(info)
        elif archive == "tar.gz":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
                members = t.getmembers()
                _safe_names([m.name for m in members])
                for m in members:
                    if m.isfile() and posixpath.basename(m.name) == binary:
                        f = t.extractfile(m)
                        if f is not None:
                            return f.read()
        else:
            raise ToolError(f"formato archivio non gestito: {archive}")
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError) as e:
        raise ToolError(f"archivio non valido: {e}")
    raise ToolError(f"il file '{binary}' non è nell'archivio")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _install_pypi(proj: Path, e: dict, run: Callable) -> Optional[str]:
    venv = proj / VENV_REL
    py = venv / "bin" / "python"
    if not py.is_file():
        r = run([sys.executable, "-m", "venv", str(venv)], capture_output=True, text=True)
        if r.returncode != 0:
            raise ToolError(f"creazione del virtualenv fallita: {(r.stderr or r.stdout).strip()[-500:]}")
    spec = f"{e['binary']}=={e['version']}"
    r = run([str(py), "-m", "pip", "install", "--disable-pip-version-check", spec], capture_output=True, text=True)
    if r.returncode != 0:
        raise ToolError(f"pip install {spec} fallito: {(r.stderr or r.stdout).strip()[-500:]}")
    m = re.search(r"sha256[:=]([0-9a-f]{64})", (r.stdout or "") + (r.stderr or ""))
    return m.group(1) if m else None


def install(proj: Path, tool: str, approved_by: str, fetch: Callable[[str], bytes] = urllib_fetch,
            run: Callable = subprocess.run, os_: Optional[str] = None, arch: Optional[str] = None) -> dict:
    """Scarica, verifica SHA256, estrae in .kynfra/bin (Checkov: venv) e aggiorna il registro. Ritorna la voce."""
    if not approved_by or not approved_by.strip():
        raise ToolError("--approved-by è obbligatorio (utente git che approva questo strumento)")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ToolError("non eseguire come root né con sudo: gli strumenti si installano nel progetto")
    e = _entry(tool)
    name = canonical(tool)
    if os_ is None or arch is None:
        os_, arch = detect_platform()
    plan = plan_install(proj, name, os_, arch)
    dest = Path(plan["dest"])
    if e["kind"] == "pypi":
        sha = _install_pypi(proj, e, run)
        bin_sha = sha256_file(dest) if dest.is_file() else None
        entry = {"version": e["version"], "source": "pypi", "sha256": sha, "binary_sha256": bin_sha}
    else:
        check_url(plan["url"])
        check_url(plan["sha256_url"])
        sums = fetch(plan["sha256_url"]).decode("utf-8", "replace")
        filename = posixpath.basename(urllib.parse.urlparse(plan["url"]).path)
        expected = _parse_sums(sums, filename)
        if expected is None:
            raise ToolError(f"{filename} non è nel file dei checksum ufficiale: installazione annullata")
        data = fetch(plan["url"])
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ToolError(f"checksum SHA256 non corrispondente per {filename} (atteso {expected}, ottenuto "
                            f"{actual}): installazione annullata, nulla è stato scritto")
        content = _extract_binary(data, e["archive"], e["binary"])
        _atomic_write(dest, content, 0o755)
        entry = {"version": e["version"], "source": plan["url"], "sha256": actual,
                 "binary_sha256": hashlib.sha256(content).hexdigest()}
    entry.update(installed_at=_now(), approved_by=approved_by.strip())
    lock = read_lock(proj)
    lock["tools"][name] = entry
    write_lock(proj, lock)
    return dict(entry, tool=name, path=str(dest))


# ------------------------------------------------------------------ risoluzione e verifica

def _tool_of_binary(binary: str) -> Optional[str]:
    for name, e in catalog().items():
        if e["binary"] == binary:
            return name
    return None


def _candidates(proj: Path, name: str) -> List[Path]:
    return [proj / BIN_REL / name, proj / VENV_REL / "bin" / name]


def resolve_binary(proj: Path, name: str) -> Optional[str]:
    """.kynfra/bin -> .kynfra/venv/bin -> PATH. Un binario locale il cui SHA256 non coincide con il registro
    non è affidabile e viene saltato (verify_lock lo segnala)."""
    tool = _tool_of_binary(name)
    locked = read_lock(proj)["tools"].get(tool) if tool else None
    for cand in _candidates(proj, name):
        if cand.is_file() and os.access(cand, os.X_OK):
            want = (locked or {}).get("binary_sha256")
            if want and sha256_file(cand) != want:
                continue
            return str(cand)
    return shutil.which(name)


def installed_version(path: str, tool: str) -> Optional[str]:
    """Testo dell'output di `<bin> --version` (`version` per terraform/tofu); None se non eseguibile."""
    arg = "version" if tool in ("terraform", "opentofu") else "--version"
    try:
        r = subprocess.run([path, arg], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return (r.stdout + r.stderr).strip() if r.returncode == 0 else None


def verify_lock(proj: Path) -> List[str]:
    """Differenze tra i binari presenti e il registro (lista vuota = tutto coerente)."""
    problems: List[str] = []
    cat = catalog()
    for name, rec in sorted(read_lock(proj)["tools"].items()):
        e = cat.get(name)
        if e is None:
            problems.append(f"{name}: nel registro ma fuori catalogo")
            continue
        path = _binary_path(proj, e)
        if not path.is_file():
            problems.append(f"{name}: nel registro ma il binario manca ({path})")
            continue
        want = rec.get("binary_sha256")
        if want and sha256_file(path) != want:
            problems.append(f"{name}: lo SHA256 del binario non coincide con il registro")
        if name in NO_VERSION_CHECK:
            continue
        out = installed_version(str(path), name)
        if out is None:
            problems.append(f"{name}: impossibile leggere la versione di {path}")
        elif rec.get("version") and rec["version"] not in out:
            problems.append(f"{name}: versione installata diversa dal registro (registro {rec['version']})")
    return problems


def status(proj: Path, cfg: dict) -> List[dict]:
    """Per ogni strumento del catalogo: {tool, required, wanted, found, path, in_lock, ok}."""
    cat = catalog()
    iac = "opentofu" if cfg.get("iac") == "opentofu" else "terraform"
    scanner = "trivy" if cfg.get("scanner") == "trivy" else "checkov"
    required = {iac, "tflint", "tflint_ruleset_aws", scanner}
    lock = read_lock(proj)["tools"]
    problems = verify_lock(proj)
    rows = []
    for name, e in sorted(cat.items()):
        path = resolve_binary(proj, e["binary"])
        found = None
        if path and name not in NO_VERSION_CHECK:
            out = installed_version(path, name)
            found = e["version"] if out and e["version"] in out else (out.splitlines()[0] if out else None)
        elif path:
            found = lock.get(name, {}).get("version")
        in_lock = name in lock
        ok = bool(path) and found == e["version"] and not any(p.startswith(f"{name}:") for p in problems)
        rows.append({"tool": name, "required": name in required, "wanted": e["version"], "found": found,
                     "path": path, "in_lock": in_lock, "ok": ok})
    return rows


# ------------------------------------------------------------------ CLI

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="tools.py", description="Strumenti esterni di kynfra")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("verify")
    p_plan = sub.add_parser("plan")
    p_plan.add_argument("tools", nargs="*")
    p_inst = sub.add_parser("install")
    p_inst.add_argument("tools", nargs="*")
    p_inst.add_argument("--approved-by", default="")
    args = ap.parse_args(argv)
    import rules
    proj = rules.find_project_dir(None)
    try:
        if args.cmd == "status":
            cfg = rules.load_config(proj) or {}
            for r in status(proj, cfg):
                flag = "ok" if r["ok"] else ("MANCA" if not r["path"] else "NON CONFORME")
                req = "richiesto" if r["required"] else "opzionale"
                print(f"{r['tool']:20} {req:10} atteso {r['wanted']:10} trovato {r['found'] or '-':10} "
                      f"registro {'si' if r['in_lock'] else 'no':2} {flag}")
            return 0
        if args.cmd == "verify":
            problems = verify_lock(proj)
            for p in problems:
                print(p)
            if not problems:
                print("Registro coerente con i binari installati.")
            return 1 if problems else 0
        if len(args.tools) != 1:
            print("uno strumento per volta: indica esattamente un nome (es. `tools.py install tflint`)",
                  file=sys.stderr)
            return 2
        tool = args.tools[0]
        if args.cmd == "plan":
            os_, arch = detect_platform()
            print(plan_install(proj, tool, os_, arch)["approval_text"])
            return 0
        rec = install(proj, tool, args.approved_by)
        print(f"Installato {rec['tool']} {rec['version']} in {rec['path']} (approvato da {rec['approved_by']}).")
        return 0
    except ToolError as e:
        print(f"errore: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
