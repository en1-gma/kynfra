"""Lexer di shell per la guardia di kynfra: scompone un comando in comandi semplici (parole, redirect, heredoc),
gestendo virgolette, escape, `$'…'`, `$(…)`, backtick, `<(…)` e heredoc, e raccoglie le sostituzioni di comando
da analizzare a parte. Solo libreria standard.
"""
from __future__ import annotations

import codecs
import re
import warnings
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

@dataclass
class Word:
    parts: List[Tuple[str, str, bool]] = field(default_factory=list)  # (lit|var|pvar|sub|dyn, valore, quotato)

    def add(self, kind: str, value: str, quoted: bool) -> None:
        self.parts.append((kind, value, quoted))


@dataclass
class Cmd:
    words: List[Word] = field(default_factory=list)
    redirs: List[Tuple[str, Word]] = field(default_factory=list)
    stdin: List[Word] = field(default_factory=list)  # heredoc e herestring
    pipeline: int = 0
    pos: int = 0
    name: str = ""
    download: bool = False
    stdin_exec: bool = False
    writes: bool = False

    def empty(self) -> bool:
        return not self.words and not self.redirs and not self.stdin


REDIR_RE = re.compile(r"(?:\d+|\{[A-Za-z_]\w*\})?(?:&>>|&>|>>|>\||>&|>|<<<|<<-|<<|<>|<&|<)")
WORD_END = set(" \t\r\n;&|()<>")


def _ansi_c(raw: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return codecs.decode(raw.encode("latin-1", "backslashreplace"), "unicode_escape")
        except Exception:
            return raw.replace("\\", "")


class Lexer:
    """Scompone un testo di shell in comandi semplici, raccogliendo le sostituzioni di comando da analizzare."""

    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.n = len(text)
        self.subs: List[str] = []

    def parse(self, stop: Optional[str] = None) -> List[Cmd]:
        s = self.s
        cmds: List[Cmd] = []
        state = {"cur": Cmd(), "pipeline": 0, "pos": 0}
        pending: List[Tuple[Cmd, str, bool, bool]] = []
        depth = 0

        def finish(pipe: bool) -> None:
            cur = state["cur"]
            if not cur.empty():
                cur.pipeline, cur.pos = state["pipeline"], state["pos"]
                cmds.append(cur)
                if pipe:
                    state["pos"] += 1
                else:
                    state["pipeline"] += 1
                    state["pos"] = 0
            elif not pipe:
                state["pipeline"] += 1
                state["pos"] = 0
            state["cur"] = Cmd()

        while self.i < self.n:
            c = s[self.i]
            if c in " \t\r":
                self.i += 1
                continue
            if s.startswith("\\\n", self.i):
                self.i += 2
                continue
            if c == "\n":
                self.i += 1
                finish(False)
                for cmd, delim, strip, quoted in pending:
                    self._heredoc(cmd, delim, strip, quoted)
                pending = []
                continue
            if c == "#":
                j = s.find("\n", self.i)
                self.i = self.n if j < 0 else j
                continue
            if c == ")" and depth == 0 and stop == ")":
                self.i += 1
                finish(False)
                return cmds
            m = REDIR_RE.match(s, self.i)
            if m and not (c in "<>" and s.startswith("(", self.i + 1)):
                op = re.sub(r"^(?:\d+|\{\w+\})", "", m.group(0))
                self.i = m.end()
                while self.i < self.n and s[self.i] in " \t":
                    self.i += 1
                w, raw = self._word()
                if op in ("<<", "<<-"):
                    quoted = any(q in raw for q in "'\"\\")
                    delim = raw.replace("'", "").replace('"', "").replace("\\", "")
                    pending.append((state["cur"], delim, op == "<<-", quoted))
                elif op == "<<<":
                    state["cur"].stdin.append(w)
                else:
                    state["cur"].redirs.append((op, w))
                continue
            if c in ";&|()":
                two = s[self.i:self.i + 2]
                if two in ("&&", "||", ";;", ";&"):
                    self.i += 2
                    finish(False)
                elif two == "|&":
                    self.i += 2
                    finish(True)
                else:
                    self.i += 1
                    if c == "(":
                        depth += 1
                    elif c == ")" and depth > 0:
                        depth -= 1
                    finish(c == "|")
                continue
            w, _ = self._word()
            state["cur"].words.append(w)
        finish(False)
        for cmd, delim, strip, quoted in pending:
            self._heredoc(cmd, delim, strip, quoted)
        return cmds

    def _word(self) -> Tuple[Word, str]:
        s = self.s
        start = self.i
        w = Word()
        buf: List[str] = []

        def flush() -> None:
            if buf:
                w.add("lit", "".join(buf), False)
                buf.clear()

        if self.i < self.n and s[self.i] in "<>" and s.startswith("(", self.i + 1):
            self.i += 2
            w.add("sub", self._until_paren(), False)
            return w, s[start:self.i]
        while self.i < self.n:
            c = s[self.i]
            if c in WORD_END:
                break
            if c == "\\":
                if self.i + 1 < self.n:
                    nxt = s[self.i + 1]
                    self.i += 2
                    if nxt != "\n":
                        flush()
                        w.add("lit", nxt, True)
                else:
                    self.i += 1
                continue
            if c == "'":
                flush()
                j = s.find("'", self.i + 1)
                j = self.n if j < 0 else j
                w.add("lit", s[self.i + 1:j], True)
                self.i = j + 1
                continue
            if c == '"':
                flush()
                self.i += 1
                self._dq(w, end_quote=True)
                continue
            if c == "$":
                flush()
                self._dollar(w, quoted=False)
                continue
            if c == "`":
                flush()
                self._backtick(w, quoted=False)
                continue
            buf.append(c)
            self.i += 1
        flush()
        return w, s[start:self.i]

    def _dq(self, w: Word, end_quote: bool) -> None:
        s = self.s
        buf: List[str] = []

        def flush() -> None:
            if buf:
                w.add("lit", "".join(buf), True)
                buf.clear()

        while self.i < self.n:
            c = s[self.i]
            if c == '"' and end_quote:
                self.i += 1
                break
            if c == "\\" and self.i + 1 < self.n and s[self.i + 1] in '$`"\\\n':
                if s[self.i + 1] != "\n":
                    buf.append(s[self.i + 1])
                self.i += 2
                continue
            if c == "$":
                flush()
                self._dollar(w, quoted=True)
                continue
            if c == "`":
                flush()
                self._backtick(w, quoted=True)
                continue
            buf.append(c)
            self.i += 1
        flush()

    def _until_paren(self) -> str:
        """Testo fino alla `)` che chiude (self.i è subito dopo la `(`), rispettando quoting e heredoc."""
        start = self.i
        sub = Lexer(self.s)
        sub.i = self.i
        sub.parse(stop=")")
        self.i = sub.i
        inner = self.s[start:max(start, self.i - 1)]
        self.subs.append(inner)
        return inner

    def _dollar(self, w: Word, quoted: bool) -> None:
        s = self.s
        i = self.i
        nxt = s[i + 1:i + 2]
        if nxt == "'" and not quoted:
            j = i + 2
            while j < self.n and s[j] != "'":
                j += 2 if s[j] == "\\" else 1
            w.add("lit", _ansi_c(s[i + 2:j]), True)
            self.i = j + 1
            return
        if nxt == '"' and not quoted:
            self.i = i + 2
            self._dq(w, end_quote=True)
            return
        if nxt == "(":
            arith = s.startswith("$((", i)
            self.i = i + 2
            inner = self._until_paren()
            if arith and self.i < self.n and s[self.i] == ")":
                self.i += 1
            w.add("dyn" if arith else "sub", inner, quoted)
            return
        if nxt == "{":
            j, level = i + 2, 1
            while j < self.n and level:
                if s[j] == "{":
                    level += 1
                elif s[j] == "}":
                    level -= 1
                j += 1
            inner = s[i + 2:j - 1]
            self.i = j
            if re.fullmatch(r"[A-Za-z_]\w*", inner):
                w.add("var", inner, quoted)
            else:
                if "$(" in inner or "`" in inner:
                    sub = Lexer(inner)
                    sub._dq(Word(), end_quote=False)
                    self.subs += sub.subs
                w.add("pvar", inner, quoted)
            return
        m = re.match(r"[A-Za-z_]\w*", s[i + 1:i + 200])
        if m:
            w.add("var", m.group(0), quoted)
            self.i = i + 1 + m.end()
            return
        if nxt and nxt in "@*#?$!-0123456789":
            w.add("dyn", nxt, quoted)
            self.i = i + 2
            return
        w.add("lit", "$", quoted)
        self.i = i + 1

    def _backtick(self, w: Word, quoted: bool) -> None:
        s = self.s
        j = self.i + 1
        buf: List[str] = []
        while j < self.n and s[j] != "`":
            if s[j] == "\\" and j + 1 < self.n:
                buf.append(s[j + 1] if s[j + 1] in "`\\$" else s[j:j + 2])
                j += 2
                continue
            buf.append(s[j])
            j += 1
        inner = "".join(buf)
        self.i = j + 1
        self.subs.append(inner)
        w.add("sub", inner, quoted)

    def _heredoc(self, cmd: Cmd, delim: str, strip: bool, quoted: bool) -> None:
        lines: List[str] = []
        while self.i < self.n:
            j = self.s.find("\n", self.i)
            line = self.s[self.i:j if j >= 0 else self.n]
            self.i = j + 1 if j >= 0 else self.n
            cmp = line.lstrip("\t") if strip else line
            if cmp == delim:
                break
            lines.append(cmp)
        body = "\n".join(lines)
        w = Word()
        if quoted:
            w.add("lit", body, True)
        else:
            sub = Lexer(body)
            sub._dq(w, end_quote=False)
            self.subs += sub.subs
        cmd.stdin.append(w)
