"""Lettori di ricette per la guardia di kynfra: testo dei comandi che `make`, `just`, `task` eseguirebbero
(dipendenze e variabili comprese) e lettura sicura dei file di script. Lettura euristica: ciò che non si risolve
diventa una variabile ignota (`$__kynfra_…`), che la guardia tratta come non determinabile.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

MAX_FILE = 512 * 1024


def read_text(p: Path) -> Optional[str]:
    try:
        if not p.is_file() or p.stat().st_size > MAX_FILE:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def _strip_recipe_prefix(line: str) -> str:
    return re.sub(r"^[\s@+-]+", "", line)


def _balanced(text: str, start: int) -> int:
    """Indice dopo la parentesi che chiude quella aperta in text[start-1]."""
    level, j = 1, start
    while j < len(text) and level:
        if text[j] == "(":
            level += 1
        elif text[j] == ")":
            level -= 1
        j += 1
    return j


def _make_lines(mf: Path, seen: Set[Path]) -> List[str]:
    if mf in seen or len(seen) > 20:
        return []
    seen.add(mf)
    text = read_text(mf) or ""
    text = re.sub(r"\\\n[ \t]*", " ", text)
    out: List[str] = []
    for line in text.split("\n"):
        m = re.match(r"^\s*-?s?include\s+(.+)$", line)
        if m and not line.startswith("\t"):
            for name in m.group(1).split():
                for inc in sorted(mf.parent.glob(name)) if re.search(r"[*?\[]", name) else [mf.parent / name]:
                    if inc.is_file():
                        out += _make_lines(inc, seen)
            continue
        out.append(line)
    return out


def make_recipes(mf: Path, goals: List[str], overrides: Dict[str, str]) -> str:
    """Testo delle ricette che `make <goals>` eseguirebbe (con dipendenze e variabili), più i `$(shell …)`."""
    lines = _make_lines(mf.resolve(), set())
    mvars: Dict[str, str] = {"MAKE": "make", "SHELL": "/bin/sh", "CURDIR": str(mf.parent)}
    rules_: Dict[str, Tuple[List[str], List[str]]] = {}
    first: Optional[str] = None
    cur: Optional[List[str]] = None
    shell_cmds: List[str] = []
    define: Optional[str] = None
    buf: List[str] = []
    for raw in lines:
        if define is not None:
            if raw.strip() == "endef":
                mvars[define] = "\n".join(buf)
                define, buf = None, []
            else:
                buf.append(raw)
            continue
        if raw.startswith("\t"):
            if cur is not None:
                for t in cur:
                    rules_[t][1].append(raw[1:])
            continue
        line = re.sub(r"(?<!\\)#.*$", "", raw)
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^(?:override\s+|export\s+)*define\s+(\S+)", s)
        if m:
            define = m.group(1)
            continue
        m = re.match(r"^(?:override\s+|export\s+|private\s+)*([A-Za-z_.][\w.-]*)\s*(::?=|:::=|\?=|\+=|!=|=)\s*(.*)$", s)
        if m:
            name, op, val = m.groups()
            if op == "!=":
                shell_cmds.append(val)
                mvars[name] = "$(__kynfra_shell)"
            elif op == "+=":
                mvars[name] = (mvars.get(name, "") + " " + val).strip()
            elif op == "?=":
                mvars.setdefault(name, val)
            else:
                mvars[name] = val
            cur = None
            continue
        if re.match(r"^(?:ifeq|ifneq|ifdef|ifndef|else|endif|export|unexport|vpath|override)\b", s):
            continue
        m = re.match(r"^([^:=]+?)\s*::?(?!=)\s*(.*)$", s)
        if m:
            targets = m.group(1).split()
            rest = m.group(2)
            inline = None
            if ";" in rest:
                rest, inline = rest.split(";", 1)
            if re.match(r"^\s*[A-Za-z_][\w.-]*\s*(?:[:+?]?=)", rest):
                cur = None
                continue
            cur = targets
            for t in targets:
                entry = rules_.setdefault(t, ([], []))
                entry[0].extend(rest.replace("|", " ").split())
                if inline and inline.strip():
                    entry[1].append(inline)
                if first is None and not t.startswith(".") and "%" not in t:
                    first = t
            continue
        cur = None
    mvars.update(overrides)
    whole = "\n".join(lines)
    for m in re.finditer(r"\$[({]shell\s", whole):
        end = _balanced(whole, m.start() + 2)
        shell_cmds.append(whole[m.end():end - 1])

    def expand(text: str, target: str = "", stem: str = "") -> str:
        text = text.replace("$$", "\0")
        text = re.sub(r"\$(?:@|\(@\)|\{@\})", lambda _m: target, text)
        text = re.sub(r"\$(?:\*|\(\*\)|\{\*\})", lambda _m: stem or target, text)
        text = re.sub(r"\$[<^+?|]", "x", text)
        for _ in range(10):
            new = re.sub(r"\$[({]([A-Za-z_.][\w.-]*)[)}]",
                         lambda mm: mvars[mm.group(1)] if mm.group(1) in mvars else "$__kynfra_mk_" +
                         re.sub(r"\W", "_", mm.group(1)), text)
            if new == text:
                break
            text = new
        return text.replace("\0", "$")

    goals = goals or ([mvars[".DEFAULT_GOAL"].strip()] if mvars.get(".DEFAULT_GOAL") else [first] if first else [])
    out = [expand(c) for c in shell_cmds]
    seen: Set[str] = set()
    queue = list(goals)
    fallback = False
    while queue:
        g = queue.pop(0)
        if g in seen or len(seen) > 500:
            continue
        seen.add(g)
        if g in rules_:
            prereqs, recipes = rules_[g]
            out += [_strip_recipe_prefix(expand(r, g)) for r in recipes]
            queue += expand(" ".join(prereqs), g).split()
            continue
        matched = False
        for pat, (prereqs, recipes) in rules_.items():
            if "%" not in pat:
                continue
            m = re.fullmatch(re.escape(pat).replace("%", "(.+)"), g)
            if m:
                matched = True
                out += [_strip_recipe_prefix(expand(r, g, m.group(1))) for r in recipes]
                queue += expand(" ".join(prereqs).replace("%", m.group(1)), g).split()
        if not matched and g in goals:
            fallback = True
    if fallback:
        out += [_strip_recipe_prefix(expand(r, t)) for t, (_, recipes) in rules_.items() for r in recipes]
    return "\n".join(out)


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def just_recipes(jf: Path, names: List[str]) -> str:
    """Testo delle ricette di un justfile che `just <names>` eseguirebbe (dipendenze comprese)."""
    lines = (read_text(jf) or "").split("\n")
    jvars: Dict[str, str] = {}
    recipes: Dict[str, Tuple[List[str], List[str]]] = {}
    aliases: Dict[str, str] = {}
    order: List[str] = []
    shell_cmds: List[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        i += 1
        if not ln.strip() or ln[0] in " \t" or ln.startswith(("#", "[", "set ", "import ", "mod ")):
            continue
        m = re.match(r"^alias\s+([\w-]+)\s*:=\s*([\w-]+)", ln)
        if m:
            aliases[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^(?:export\s+)?([A-Za-z_][\w-]*)\s*:=\s*(.*)$", ln)
        if m:
            val = m.group(2).strip()
            if val.startswith("`"):
                shell_cmds.append(val.strip("`"))
            jvars[m.group(1)] = _unquote(val)
            continue
        m = re.match(r"^@?([A-Za-z_][\w-]*)([^:]*?):(?!=)(.*)$", ln)
        if not m:
            continue
        name, deps_text = m.group(1), m.group(3)
        deps = [d for d in re.sub(r"\([^)]*\)|&&", " ", deps_text).split() if re.fullmatch(r"[\w-]+", d)]
        body: List[str] = []
        while i < len(lines) and (not lines[i].strip() or lines[i][0] in " \t"):
            body.append(lines[i].strip())
            i += 1
        recipes[name] = (deps, body)
        order.append(name)

    def sub(text: str) -> str:
        return re.sub(r"\{\{\s*([^}]*?)\s*\}\}", lambda mm: jvars.get(mm.group(1), "$__kynfra_just_" + re.sub(
            r"\W", "_", mm.group(1))), text)

    wanted = [aliases.get(n, n) for n in names if aliases.get(n, n) in recipes]
    if not wanted:
        wanted = list(order) if names else order[:1]
    out = [sub(c) for c in shell_cmds]
    seen: Set[str] = set()
    queue = list(wanted)
    while queue:
        r = queue.pop(0)
        if r in seen or r not in recipes:
            continue
        seen.add(r)
        deps, body = recipes[r]
        queue += deps
        text = "\n".join(sub(_strip_recipe_prefix(b)) for b in body if b)
        if body and body[0].startswith("#!") and re.search(r"python|node|ruby|perl|php|deno|bun", body[0]):
            out.append("python3 -c " + shlex.quote(text))
        else:
            out.append(text)
    return "\n".join(out)


def task_recipes(tf: Path, names: List[str], overrides: Dict[str, str]) -> str:
    """Comandi dei task di un Taskfile che `task <names>` eseguirebbe (lettura euristica dello YAML)."""
    lines = (read_text(tf) or "").split("\n")
    tvars: Dict[str, str] = {}
    blocks: Dict[str, List[str]] = {}
    section = None
    child_indent = None
    cur = None
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        ind = len(ln) - len(ln.lstrip(" "))
        if ind == 0:
            section = ln.split(":", 1)[0].strip()
            child_indent = None
            continue
        if section == "vars":
            m = re.match(r"^\s+([\w-]+)\s*:\s*(.+)$", ln)
            if m and not m.group(2).strip().startswith(("{", "|")):
                tvars[m.group(1)] = _unquote(m.group(2))
        if section != "tasks":
            continue
        if child_indent is None:
            child_indent = ind
        if ind == child_indent:
            m = re.match(r"^\s*['\"]?([\w:.*-]+)['\"]?\s*:\s*(.*)$", ln)
            if m:
                cur = m.group(1)
                blocks[cur] = [m.group(2)] if m.group(2).strip() else []
            continue
        if cur is not None:
            blocks[cur].append(ln)
    tvars.update(overrides)
    shell_cmds = [_unquote(m.group(1)) for ln in lines for m in [re.match(r"^\s*(?:-\s*)?sh\s*:\s*(.+)$", ln)] if m]

    def sub(text: str) -> str:
        return re.sub(r"\{\{\s*\.?([^}]*?)\s*\}\}", lambda mm: tvars.get(mm.group(1), "$__kynfra_task_" + re.sub(
            r"\W", "_", mm.group(1))), text)

    def commands(block: List[str]) -> Tuple[List[str], List[str]]:
        cmds, deps = [], []
        in_deps = False
        for ln in block:
            s = ln.strip()
            item = s.startswith("- ")
            if item:
                s = s[2:].strip()
            m = re.match(r"^deps\s*:\s*(.*)$", s)
            if m:
                inline = m.group(1).strip()
                in_deps = not inline
                deps += [_unquote(d) for d in inline.strip("[]").split(",") if d.strip()]
                continue
            m = re.match(r"^task\s*:\s*(\S+)", s)
            if m:
                deps.append(_unquote(m.group(1)))
                continue
            if in_deps and item:
                deps.append(_unquote(s))
                continue
            m = re.match(r"^(?:cmd|cmds|sh)\s*:\s*(.*)$", s)
            if m:
                in_deps = False
                s = m.group(1).strip()
                if not s:
                    continue
            elif re.match(r"^[\w-]+\s*:(?:\s|$)", s):
                in_deps = False
                continue
            if s in ("|", ">", "|-", ">-", "|+", ">+", ""):
                continue
            cmds.append(sub(_unquote(s)))
        return cmds, deps

    wanted = names or ["default"]
    fallback = any(n not in blocks for n in wanted)
    out = [sub(c) for c in shell_cmds]
    seen: Set[str] = set()
    queue = list(blocks) if fallback else list(wanted)
    while queue:
        n = queue.pop(0)
        if n in seen or n not in blocks:
            continue
        seen.add(n)
        cmds, deps = commands(blocks[n])
        out += cmds
        queue += deps
    return "\n".join(out)
