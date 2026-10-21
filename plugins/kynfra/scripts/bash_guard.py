#!/usr/bin/env python3
"""PreToolUse su Bash (Claude Code) e sulla shell di Codex: impedisce all'agente di toccare gli account cloud,
di scaricare strumenti fuori da `tools.py` e di scrivere da shell i file IaC o protetti.

Nega:
- `terraform`/`tofu` (anche `tf`, `terragrunt`, percorsi assoluti, `.kynfra/bin/terraform`) salvo i sottocomandi di
  sola lettura (`fmt`, `validate`, `version`, `providers`, `graph`, `show`, `output -json`, `state list|show`,
  `workspace list|show|select`, `init -backend=false`); ogni assegnazione `TF_CLI_ARGS*`;
- le CLI cloud in modalità mutante: `aws` (consentiti `get-*`, `describe-*`, `list-*`, `s3 ls`, `s3api head-*`),
  `kubectl` (salvo `get`/`describe`/`explain`/`version`/`config view|get-contexts`), `helm` (salvo
  `template`/`lint`/`show`/`version`/`list`/`status`), `az`, `gcloud`, `vercel` e simili; il codice inline che usa
  gli SDK cloud o lancia questi comandi;
- download e installazioni di strumenti (`curl | sh`, `curl -o`, `wget`, gestori di pacchetti, `pip install`,
  `npm i -g`, `go install`, `tfenv`…): gli strumenti si installano con `tools.py install <tool>`, uno per comando;
- le scritture da shell dei file IaC sotto `infra_root`, dei `.env*`, degli hook di git e dei file protetti
  (`.kynfra/`, kit, impostazioni dell'agente), `git apply`/`patch`, `install.sh --force/--uninstall`, i link
  (`ln`, `link`, `cp -s/-l`) creati sotto `infra_root`;
- la lettura di credenziali (`~/.aws/credentials`, cache SSO/CLI) e dei `.env*` con comandi che ne mostrano il
  contenuto.

`tools.py install <tool>` ben formato non si nega ma chiede conferma all'utente (`ask` in Claude Code; in Codex,
che non supporta `ask`, si nega con il comando da far eseguire all'utente).

Il comando viene scomposto come farebbe la shell (virgolette, escape, `;`/`&&`/`||`/`|`/a capo, `$(…)` e backtick,
heredoc, variabili assegnate nel comando, alias, funzioni) e i comandi che ne lanciano altri (`env`, `sudo`,
`nohup`, `xargs`, `bash -c`, `eval`, `docker run`, `ssh`…) vengono analizzati ricorsivamente. Le ricette di
`make`/`npm run`/`just`/`task` e gli script del repo lanciati dall'agente vengono letti e controllati con le
stesse regole; se il file non esiste o non è leggibile il comando è consentito (restano lo stop gate e la CI).

È un controllo euristico: ciò che non si può determinare (comando in una variabile ignota, script da pipe,
percorso di scrittura calcolato) viene rifiutato. La barriera decisiva contro `apply` resta che la sessione
dell'agente non ha credenziali cloud, più lo stop gate e la CI. Lexer in `shell_lex.py`, lettori di ricette in
`shell_recipes.py`.
"""
from __future__ import annotations

import glob as globmod
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hook_common as hc  # noqa: E402
import rules  # noqa: E402
from shell_lex import Cmd, Lexer, Word  # noqa: E402
from shell_recipes import just_recipes, make_lines, make_recipes, read_text as _read_text, task_recipes  # noqa: E402

PLUGIN_DIR = Path(__file__).resolve().parents[1]
KIT_REL = "tools/kynfra/plugins/kynfra"
KIT_SCRIPTS = ("arch_check", "stop_gate", "generate", "tools")
MAX_DEPTH = 10
UNKNOWN_DIR = Path("/__kynfra_cartella_ignota__")

PROTECTED_RE = re.compile(
    r"\.kynfra\b|tools/kynfra\b|\.codex/(?:hooks\.json|config\.toml|agents)"
    r"|\.claude/(?:settings(?:\.local)?\.json|rules/kynfra)|\.agents/skills/kynfra|kynfra-check\.ya?ml"
    r"|disableallhooks|claude_project_dir|kynfra_project_dir|\.terraform\.lock\.hcl", re.I)
TF_CLI_RE = re.compile(r"\bTF_CLI_ARGS\w*=")
ASSIGN_RE = re.compile(r"^([A-Za-z_]\w*)\+?=(.*)$", re.S)
# Variabili d'ambiente che fanno eseguire codice o caricare file in più a git, shell, interpreti, loader e make.
# "cmd": il valore è un comando e si analizza come script; "deny": rifiutata; "file": rifiutata se il valore
# può essere un file (`ENV=prod` resta consentito); "path": PATH, consentito solo se le nuove cartelle vanno
# dopo `$PATH`.
EXEC_ENV = {
    **dict.fromkeys(("GIT_SSH_COMMAND", "GIT_SSH", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "PAGER",
                     "MANPAGER", "EDITOR", "VISUAL", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_PROXY_COMMAND",
                     "RSYNC_RSH"), "cmd"),
    **dict.fromkeys(("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG",
                     "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR", "GIT_DIR",
                     "BASH_ENV", "PROMPT_COMMAND", "PS0", "PS1", "PS4", "SHELLOPTS", "BASHOPTS", "ZDOTDIR",
                     "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
                     "DYLD_FRAMEWORK_PATH", "DYLD_FALLBACK_LIBRARY_PATH", "NODE_OPTIONS", "NODE_PATH",
                     "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONUSERBASE", "PERL5OPT", "PERL5LIB",
                     "PERLLIB", "RUBYOPT", "RUBYLIB", "MAKEFILES", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS",
                     "LESSOPEN", "LESSCLOSE", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "HOME", "XDG_CONFIG_HOME"),
                  "deny"),
    "ENV": "file",
    "PATH": "path",
}
EXEC_ENV_RE = re.compile(r"GIT_CONFIG_(?:KEY|VALUE)_\d+")
# GIT_TRACE*: un valore che non è 0/1/2-9/true/false è il file in cui git scrive la traccia
GIT_TRACE_RE = re.compile(r"GIT_TRACE\w*")
# `${NOME:=valore}` / `${NOME=valore}`: assegnazione dentro un'espansione
PARAM_ASSIGN_RE = re.compile(r"([A-Za-z_]\w*):?=")
# interprete python per nome, senza percorso: solo così vale l'esenzione degli script del kit
BARE_PYTHON_RE = re.compile(r"python(?:3(?:\.\d+)?)?")
MAKE_SHELL_RE = re.compile(r"^\s*(?:(?:override|export)\s+)*(SHELL|MAKESHELL|\.SHELLFLAGS)\s*(?::::?=|[:+?!]?=)\s*(.*)$")
SAFE_SHELL_RE = re.compile(r"(?:(?:/usr|/usr/local|/opt/homebrew)?/bin/)?(?:env\s+)?(?:bash|sh|zsh|dash|ksh)")
SAFE_SHELLFLAG_RE = re.compile(r"-[a-zA-Z]+|pipefail|errexit|nounset|xtrace|posix")
SAFE_REDIRECT = {"/dev/null", "/dev/stderr", "/dev/stdout", "/dev/tty", "-"}
SAFE_OUT = {"-", "/dev/null", "/dev/stdout", "/dev/stderr"}
# percorsi che fanno leggere lo script dallo stdin o da un altro descrittore aperto dalla shell
STDIN_PATH_RE = re.compile(r"/dev/stdin|/dev/fd/\d+|/proc/[^/]+/fd/\d+")
SAFE_DYN_TARGET = re.compile(r"^(?:\$\(\s*mktemp\b|\$\{?TMPDIR\b|/tmp/|/private/tmp/|/var/folders/|/dev/)")

RESERVED = {"if", "then", "else", "elif", "fi", "do", "done", "while", "until", "in", "esac", "function", "!",
            "{", "}", "coproc"}
READONLY_CMDS = {"cat", "less", "more", "head", "tail", "ls", "grep", "egrep", "fgrep", "rg", "wc", "diff", "stat",
                 "file", "jq", "echo", "printf", "test", "[", "[[", "cd", "pwd", "realpath", "readlink", "tree", "du",
                 "sha256sum", "shasum", "md5", "md5sum", "true", "false", ":", "which", "type", "basename",
                 "dirname", "date", "whoami", "id", "uname", "hostname", "printenv", "cut", "tr", "nl", "column",
                 "sleep", "cmp", "comm", "whereis", "man"}
# git che non riscrive file del working tree (commit e push registrano solo ciò che è già su disco)
READONLY_GIT = {"diff", "log", "status", "show", "blame", "ls-files", "rev-parse", "grep", "add", "commit", "push",
                "fetch", "branch", "remote", "describe", "shortlog", "reflog", "ls-tree", "cat-file"}
WRITERS = {"tee", "sed", "gsed", "perl", "awk", "gawk", "mawk", "nawk", "yq", "cp", "mv", "install", "ln", "rsync",
           "scp", "dd", "truncate", "touch", "sort", "sponge", "ed", "ex", "vi", "vim", "nvim", "tar", "bsdtar",
           "gtar", "unzip", "7z", "7za", "7zz", "cpio", "ditto"}
EXTRACTORS = {"tar", "bsdtar", "gtar", "unzip", "funzip", "7z", "7za", "7zz", "cpio", "dd", "tee", "sponge",
              "install"}
NO_SCAN = READONLY_CMDS | WRITERS | {"mkdir", "rm", "rmdir", "chmod", "chown", "chgrp", "tflint", "checkov", "trivy",
                                     "gh", "git", "find", "kill", "set", "shopt", "unset", "return", "exit", "shift",
                                     "wait", "read", "export", "declare", "typeset", "local", "readonly", "alias",
                                     "unalias", "pytest", "tsc", "eslint", "prettier", "mktemp", "open", "code",
                                     "pgrep", "pkill", "killall"}

# comandi che producono file (decompressione, decodifica, copia di alberi): i percorsi di output sono scritture
DECOMPRESSORS = {"gunzip", "gzip", "bunzip2", "bzip2", "unxz", "xz", "unzstd", "zstd", "uncompress", "unlzma",
                 "lzma"}
PRODUCERS = DECOMPRESSORS | {"base64", "xxd", "openssl", "pax", "split", "csplit"}
DECOMP_SUFFIXES = {".gz": "", ".tgz": ".tar", ".z": "", ".bz2": "", ".tbz2": ".tar", ".xz": "", ".txz": ".tar",
                   ".zst": "", ".lzma": ""}
# git che riscrive (tutto o in parte) il working tree; checkout/switch/restore/stash/reset/mv/update-index a parte
GIT_TREE_WRITERS = {"merge", "cherry-pick", "pull", "rebase", "revert", "read-tree", "update-ref", "fast-import"}
# comandi che ricevono file IaC come argomento senza scriverli (o con controlli propri)
IAC_ARG_EXEMPT = {"terraform", "tofu", "terragrunt", "git", "aws", "kubectl", "helm", "bat", "tfsec", "terrascan"}

TF_NAME_RE = re.compile(r"(terraform|tofu|opentofu|tf|terragrunt)(?:[-_.]?v?\d[\w.]*)?")
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "pwsh"}
INTERPRETERS = {"python", "node", "deno", "bun", "ts-node", "tsx", "ruby", "perl", "php", "lua"}
CLOUD_DENIED = {"az", "gcloud", "gsutil", "bq", "vercel", "netlify", "flyctl", "fly", "doctl", "heroku", "pulumi",
                "cdk", "cdktf", "sam", "serverless", "sls", "eksctl", "copilot", "amplify", "firebase", "wrangler",
                "oci", "ibmcloud", "aliyun", "hcloud", "linode-cli", "scw"}
VERSION_HELP = {"--version", "-v", "-V", "version", "--help", "-h", "help"}
PKG_MANAGERS = {"brew", "apt", "apt-get", "aptitude", "yum", "dnf", "microdnf", "apk", "zypper", "port", "snap",
                "flatpak", "choco", "scoop", "winget", "pkg", "emerge", "nix-env", "conda", "mamba", "micromamba",
                "asdf", "mise", "rtx", "sdk", "proto", "aqua", "tenv", "tfenv", "tofuenv", "tgenv", "pyenv", "nvm",
                "volta", "fnm", "rustup", "pacman", "yay"}
PKG_SAFE = {"list", "ls", "search", "show", "info", "policy", "help", "version", "outdated", "config", "doctor",
            "deps", "uses", "leaves", "desc", "home", "commands", "shellenv", "madison", "depends", "rdepends",
            "current", "which", "where"}
ALWAYS_INSTALL = {"tfswitch", "tgswitch", "uvx", "aria2c", "axel"}
DOWNLOADERS = {"curl", "wget", "aria2c", "axel"}
SCAN_NAMES = ({"terraform", "tofu", "terragrunt", "aws", "kubectl", "helm", "eval", "make", "just", "task", "npm",
               "pnpm", "yarn", "npx", "go", "pip", "pipx", "uv", "cargo", "gem", "source", "."}
              | CLOUD_DENIED | SHELLS | INTERPRETERS | DOWNLOADERS | PKG_MANAGERS | ALWAYS_INSTALL)

# compressori che tar/sort lanciano con -I/--use-compress-program/--compress-program
COMPRESSORS = DECOMPRESSORS | {"pigz", "unpigz", "pbzip2", "lbzip2", "lz4", "lzip", "lzop", "plzip", "pixz",
                               "brotli", "pzstd", "zstdmt"}
# programmi che il guard sa analizzare come valore di un'opzione che lancia un programma
KNOWN_PROGRAMS = SCAN_NAMES | READONLY_CMDS | WRITERS | PRODUCERS | COMPRESSORS | {"git", "find"}
SYSTEM_BIN_RE = re.compile(r"^(?:/usr(?:/local)?|/opt/homebrew)?/s?bin/[^/]+$")
# opzioni di tar che lanciano un programma (GNU tar accetta anche le abbreviazioni)
TAR_PROGRAM_OPTS = ("use-compress-program", "to-command", "info-script", "new-volume-script", "rsh-command",
                    "rmt-command", "checkpoint-action")
TAR_SHORT_VALUE = set("bCfFgHIKLNTVX")

TF_DENIED = {"apply", "destroy", "import", "taint", "untaint", "plan", "force-unlock", "refresh", "test", "console",
             "login", "logout", "push", "env"}
TF_READONLY = {"fmt", "validate", "version", "graph", "show", "get", "modules", "metadata"}

AWS_VALUE_OPTS = {"--profile", "--region", "--output", "--endpoint-url", "--query", "--ca-bundle",
                  "--cli-read-timeout", "--cli-connect-timeout", "--color", "--cli-binary-format"}
KUBECTL_VALUE_OPTS = {"-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server",
                      "--token", "--as", "--as-group", "--as-uid", "--request-timeout", "--certificate-authority",
                      "--client-certificate", "--client-key", "--tls-server-name", "--cache-dir", "-v", "--v",
                      "--password", "--username", "--profile", "--profile-output", "--vmodule", "--log-file"}
# letture che restituiscono segreti in chiaro: (servizio, operazione) -> opzione che le rende tali (None = sempre);
# kubectl: risorse `secret(s)` con output che include i dati, `config view --raw`
TOOLS_INSTALL_VALUE_OPTS = {"--approved-by"}
AWS_SECRET_OPS = {
    ("secretsmanager", "get-secret-value"): None, ("secretsmanager", "batch-get-secret-value"): None,
    ("ssm", "get-parameter"): "--with-decryption", ("ssm", "get-parameters"): "--with-decryption",
    ("ssm", "get-parameters-by-path"): "--with-decryption", ("ssm", "get-parameter-history"): "--with-decryption",
    ("ec2", "get-password-data"): None, ("ecr", "get-login-password"): None,
    ("ecr", "get-authorization-token"): None, ("ecr-public", "get-login-password"): None,
    ("ecr-public", "get-authorization-token"): None, ("sts", "get-session-token"): None,
    ("sts", "get-federation-token"): None, ("sso", "get-role-credentials"): None,
    ("codeartifact", "get-authorization-token"): None, ("eks", "get-token"): None,
    ("cognito-identity", "get-credentials-for-identity"): None,
    ("cognito-identity", "get-open-id-token"): None,
    ("cognito-identity", "get-open-id-token-for-developer-identity"): None,
    ("redshift", "get-cluster-credentials"): None, ("redshift", "get-cluster-credentials-with-iam"): None,
    ("redshift-serverless", "get-credentials"): None, ("lightsail", "get-instance-access-details"): None,
    ("lightsail", "get-relational-database-master-user-password"): None,
    ("lightsail", "download-default-key-pair"): None,
}
# file di credenziali che l'agente non legge (con `~` già espanso): prefissi sotto la home
CREDENTIAL_HOME_PATHS = (".aws/credentials", ".aws/sso/cache/", ".aws/cli/cache/", ".aws/login/cache/")
# .env di esempio (senza valori veri): leggibili
ENV_TEMPLATES = (".env.example", ".env.sample", ".env.template", ".env.dist", ".env.defaults")
# comandi che mostrano il contenuto dei file che ricevono
READERS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "rg", "diff", "jq", "yq", "cut", "tr",
           "nl", "column", "cmp", "comm", "strings", "od", "xxd", "hexdump", "base64", "bat", "batcat", "sort",
           "uniq", "tac", "rev", "fold", "paste", "iconv", "awk", "gawk", "mawk", "nawk", "sed", "gsed", "view",
           "vi", "vim", "nvim", "nano", "emacs", "open", "code", "cp", "rsync", "scp", "dd", "tee", "zip", "tar"}
KUBECTL_SECRET_RESOURCES = {"secret", "secrets"}
KUBECTL_SAFE_OUTPUT = {"", "wide", "name"}
HELM_VALUE_OPTS = {"--kube-context", "--kubeconfig", "-n", "--namespace", "--registry-config", "--repository-cache",
                   "--repository-config", "--burst-limit", "--kube-apiserver", "--kube-as-user", "--kube-as-group",
                   "--kube-token", "--kube-ca-file", "--kube-tls-server-name", "--qps"}
GIT_EXEC_KEYS = {"core.hookspath", "core.fsmonitor", "core.sshcommand", "core.pager", "core.editor", "core.askpass",
                 "sequence.editor", "diff.external", "gpg.program", "gpg.ssh.program", "credential.helper",
                 "uploadpack.packobjectshook", "core.gitproxy", "ssh.variant", "merge.tool", "diff.tool"}
GIT_EXEC_KEY_RE = re.compile(r"(?:filter|diff|merge|mergetool|difftool)\..+\.(?:clean|smudge|process|textconv|driver"
                             r"|command|cmd)|pager\..+|credential\..+\.helper|alias\..+")

# codice inline (python -c, node -e, heredoc, script del repo): euristiche
SPAWN_RE = re.compile(r"subprocess|\bos\.(?:system|popen|exec\w*|spawn\w*|posix_spawn\w*|startfile)|\bpty\.spawn"
                      r"|child_process|\bexec(?:Sync|File(?:Sync)?)?\s*\(|\bspawn(?:Sync)?\s*\(|\bsystem\s*\("
                      r"|\bpopen\s*\(|IO\.popen|Open3|Bun\.(?:spawn|\$)|Deno\.(?:Command|run)|\bshell_exec"
                      r"|\bpassthru|\bproc_open|\bqx\s*[/{(\[]|%x\s*[{(\[]|__import__|\bpexpect|\bplumbum")
# ruby/perl/php/lua lanciano comandi anche senza parentesi (`system "…"`, `exec "a","b"`, `os.execute "…"`) e
# con `open` su una pipe (`open(F, "|-", …)`, `open("| cmd")`)
LOOSE_SPAWN_RE = re.compile(r"\b(?:system|exec\w*|spawn\w*|popen\w*|os\.execute|io\.popen|shell_exec|passthru"
                            r"|proc_open|pcntl_exec|syscall)\b|\bopen\b[^;\n]*['\"][^'\"]*\|")
AWK_SPAWN_RE = re.compile(r"\|\s*getline|print[^;\n]*\|\s*\"")
TICK_RE = re.compile(r"`[^`]+`")
CLOUD_WORD_RE = re.compile(r"\b(?:terraform|tofu|terragrunt|aws|az|gcloud|gsutil|kubectl|helm|vercel|pulumi|cdktf"
                           r"|cdk|eksctl)\b")
INSTALL_WORD_RE = re.compile(r"\b(?:curl|wget|brew|pipx?|pip3|apt-get|apt|yum|dnf|apk|tfenv|tfswitch|asdf|mise"
                             r"|uvx)\b")
SDK_RE = re.compile(r"\b(?:boto3|botocore|aioboto3|aiobotocore)\b|@aws-sdk/|['\"]aws-sdk['\"]"
                    r"|\bazure\.(?:mgmt|identity|storage|keyvault)|@azure/|\bgoogle\.cloud\b|@google-cloud/"
                    r"|googleapiclient|from\s+kubernetes\s+import|\bkubernetes\.client|@kubernetes/client-node"
                    r"|\bimport\s+pulumi|@pulumi/")
WRITE_RE = re.compile(r"\b(?:open|fopen|writeFile\w*|write_text|write_bytes|createWriteStream|appendFile\w*"
                      r"|copyfile\w*|copy2?|copytree|copyfileobj|move|rename\w*|replace|symlink\w*"
                      r"|file_put_contents|writeTextFile|Bun\.write|File\.(?:write|open)|IO\.write)\s*\(")
AWK_WRITE_RE = re.compile(r">>?\s*\"[^\"]+\"")
NET_RE = re.compile(r"urlretrieve|urlopen|\brequests\.|\bhttpx\b|urllib3|\bfetch\s*\(|\bhttps?\.(?:get|request)\s*\("
                    r"|\baxios\b|Net::HTTP|open-uri|LWP::|HTTP::Tiny|curl_exec|Invoke-WebRequest"
                    r"|file_get_contents\s*\(\s*['\"]https?:")
SAVE_DOWNLOAD_RE = re.compile(r"urlretrieve|\bwget\.download|\.download_file\s*\(|\bhf_hub_download")
OBFUSCATED_RE = re.compile(r"\b(?:exec|eval)\s*\([^\n]*(?:b64decode|b85decode|a85decode|decompress|fromhex"
                           r"|codecs\.decode|rot13|\bchr\s*\(|atob|Buffer\.from)")
IAC_MENTION_RE = re.compile(r"\.tf\b|\.tfvars\b|\.tf\.json\b|(?:^|[/'\"`\s])\.env|native/|\.git/hooks|\.git/config")

# definizione di funzione: `f() …`, `function f …`
FUNC_DEF_RE = re.compile(r"(?<![\w.:$-])([A-Za-z_][\w.:-]*)\s*\(\s*\)|\bfunction\s+([A-Za-z_][\w.:-]*)")

KIT, DELEGATED, RO, RW = "kit", "delegated", "ro", "rw"


# ---------------------------------------------------------------- analisi

@dataclass
class Arg:
    text: str
    dyn: bool = False
    globby: bool = False


@dataclass
class Ctx:
    cwds: List[Path]
    depth: int
    stdin: List[str] = field(default_factory=list)
    stdin_files: List[Arg] = field(default_factory=list)  # destinazioni di `<`
    piped: bool = False
    cmd: Optional[Cmd] = None
    redir_targets: List[Arg] = field(default_factory=list)
    write_redir: bool = False
    xargs: bool = False
    env: Dict[str, str] = field(default_factory=dict)

    def nested(self) -> "Ctx":
        return Ctx(self.cwds, self.depth + 1)


def norm_name(text: str, lower: bool = True) -> str:
    """Nome del comando come lo cerca la shell: basename, senza versione/tag (`terraform:1.9`, `x@latest`).
    `lower=False` per il confronto esatto (argomenti di un comando sconosciuto che seguono un'opzione)."""
    base = text.rstrip("/").rsplit("/", 1)[-1]
    if lower:
        base = base.lower()
    base = re.sub(r"\.exe$", "", base)
    if base and base[0] != "@":
        base = re.split(r"[@:]", base, maxsplit=1)[0]
    m = TF_NAME_RE.fullmatch(base)
    if m:
        name = m.group(1)
        return {"tf": "terraform", "opentofu": "tofu"}.get(name, name)
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?|pypy\d*|py", base):
        return "python"
    if re.fullmatch(r"pip(?:\d+(?:\.\d+)*)?", base):
        return "pip"
    if base == "nodejs":
        return "node"
    if re.fullmatch(r"lua(?:jit|\d+(?:\.\d+)*)?|texlua", base):
        return "lua"
    if base in ("gmake", "go-task", "pnpx", "bunx"):
        return {"gmake": "make", "go-task": "task"}.get(base, "npx")
    return base


def long_opt(x: str, names: Tuple[str, ...], exact: Set[str] = frozenset(),
             abbrev: bool = True) -> Optional[Tuple[str, Optional[str]]]:
    """`--nome[=valore]` se `nome` è una delle opzioni `names`, anche abbreviata come accetta getopt_long
    (`--use-compress=`); `exact` sono altre opzioni del comando che non vanno scambiate per abbreviazioni.
    Restituisce (nome completo, valore dopo `=` o None)."""
    if not x.startswith("--"):
        return None
    key, eq, val = x[2:].partition("=")
    if key in exact:
        return None
    for n in names:
        if n == key or (abbrev and len(key) >= 3 and n.startswith(key)):
            return n, (val if eq else None)
    return None


def _abbrev_of(arg: str, flag: str) -> bool:
    """`arg` è un'abbreviazione di `flag` (la CLI aws accetta i prefissi: `--with-d` = `--with-decryption`)."""
    key = arg.split("=", 1)[0]
    return key.startswith("--") and len(key) > 3 and flag.startswith(key)


def is_env_name(name: str) -> bool:
    return name.startswith(".env")


def brace_expand(s: str, limit: int = 64) -> List[str]:
    m = re.search(r"\{([^{}]*,[^{}]*)\}", s)
    if not m:
        return [s]
    out: List[str] = []
    for alt in m.group(1).split(","):
        out += brace_expand(s[:m.start()] + alt + s[m.end():], limit)
        if len(out) >= limit:
            break
    return out[:limit]


def _opt_split(args: List[Arg], value_opts: Set[str]) -> List[Arg]:
    """Argomenti posizionali, saltando le opzioni e i valori delle opzioni che ne hanno uno."""
    pos: List[Arg] = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        t = a.text
        if t == "--":
            continue
        if t.startswith("-") and len(t) > 1:
            if "=" not in t and t in value_opts:
                skip = True
            continue
        pos.append(a)
    return pos


class Analyzer:
    def __init__(self, proj: Path, cfg: dict, cwd: Path):
        self.proj = proj.resolve()
        self.cfg = cfg
        self.reasons: List[str] = []
        self.tool = False
        self.writes: Set[str] = set()
        self.executed: Set[str] = set()
        self.installs = 0
        # PATH, `hash`, nameref o variabili di EXEC_ENV toccati nel comando: niente esenzione del kit
        self.env_tampered = False
        # stdin dato a un gruppo (`{ …; } < f`, `( … ) < f`) o alla shell (`exec < f`): vale per tutto lo script
        self.group_stdin: List[Arg] = []
        self.funcs: Set[str] = set()  # nomi delle funzioni definite nel comando
        self.group_bodies: List[str] = []  # heredoc/herestring dati a un gruppo
        self.protect = cfg.get("rules", {}).get("protected-files", "block") != "off"
        self.vars: Dict[str, Optional[str]] = {
            "HOME": str(Path.home()), "PWD": str(cwd), "CLAUDE_PROJECT_DIR": str(self.proj),
            "KYNFRA_PROJECT_DIR": str(self.proj), "CLAUDE_PLUGIN_ROOT": str(PLUGIN_DIR)}
        for k in ("TMPDIR", "USER"):
            if os.environ.get(k):
                self.vars[k] = os.environ[k]
        self.aliases: Dict[str, str] = {}
        bases = [self.proj / KIT_REL, PLUGIN_DIR]
        self.kit_scripts = {str((b / "scripts" / f"{n}.py").resolve()) for b in bases for n in KIT_SCRIPTS}
        self.kit_install = {str((b / "install.sh").resolve()) for b in bases}
        self.kit_setup = {str((self.proj / "tools/kynfra/setup.sh").resolve())}

    # ------------------------------------------------------------ esito

    def deny(self, msg: str, tool: bool = False) -> None:
        if msg not in self.reasons:
            self.reasons.append(msg)
        self.tool = self.tool or tool

    def deny_tool(self, what: str) -> None:
        self.deny(f"download o installazione di strumenti fuori da tools.py ({what}): gli strumenti si installano "
                  "solo con /kynfra:kynfra-tools, uno alla volta e con l'approvazione dell'utente", tool=True)

    def finish(self) -> None:
        if self.writes & self.executed:
            self.deny("script scritto e lanciato nello stesso comando: il contenuto non è verificabile")
        if self.installs > 1:
            self.deny("tools.py install: un solo strumento per comando (l'approvazione vale per uno strumento)",
                      tool=True)

    # ------------------------------------------------------------ espansione

    def expand(self, w: Word) -> List[Arg]:
        out: List[str] = []
        dyn = globby = split = False
        first = w.parts[0] if w.parts else None
        assign = bool(first and first[0] == "lit" and not first[2] and ASSIGN_RE.match(first[1]))
        for kind, val, quoted in w.parts:
            if kind == "lit":
                out.append(val)
                if not quoted and re.search(r"[*?\[]|\{[^}]*,", val):
                    globby = True
            elif kind in ("var", "pvar"):
                pa = PARAM_ASSIGN_RE.match(val) if kind == "pvar" else None
                if pa and self.sensitive_name(pa.group(1)):
                    self.env_tampered = True
                    self.deny(f"`${{{pa.group(1)}:=…}}`: assegna una variabile che fa eseguire codice o cambia "
                              "le opzioni dei comandi (PATH, EXEC_ENV, TF_CLI_ARGS*)")
                m = re.match(r"([A-Za-z_]\w*)", val)
                name = m.group(1) if m and not val.startswith("#") else None
                value = self.vars.get(name) if name else None
                if value is None:
                    dyn = True
                    out.append("${" + val + "}")
                else:
                    out.append(value)
                    if not quoted and not assign and re.search(r"\s", value):
                        split = True
            elif kind == "sub":
                dyn = True
                out.append("$(" + val + ")")
            else:
                dyn = True
                out.append("$" + val)
        text = "".join(out)
        if split:
            return [Arg(t, dyn, globby) for t in text.split()]
        return [Arg(text, dyn, globby)]

    def expand_join(self, w: Word) -> str:
        return " ".join(a.text for a in self.expand(w))

    def words_of(self, text: str) -> List[Arg]:
        lx = Lexer(text)
        cmds = lx.parse()
        out: List[Arg] = []
        if cmds:
            for w in cmds[0].words:
                out += self.expand(w)
        return out

    def candidates(self, a: Arg, cwds: List[Path]) -> List[str]:
        texts = brace_expand(a.text) if a.globby else [a.text]
        out = list(texts)
        if a.globby:
            for t in texts:
                if not re.search(r"[*?\[]", t):
                    continue
                pat = os.path.expanduser(t)
                roots = [None] if os.path.isabs(pat) else [c for c in cwds if c != UNKNOWN_DIR]
                for r in roots:
                    try:
                        found = globmod.glob(pat, root_dir=str(r)) if r else globmod.glob(pat)
                    except Exception:
                        found = []
                    out += found[:200]
        return out

    def resolve_all(self, text: str, cwds: List[Path]) -> List[Path]:
        t = os.path.expanduser(text)
        if os.path.isabs(t):
            return [Path(t).resolve()]
        return [(c / t).resolve() for c in cwds if c != UNKNOWN_DIR]

    # ------------------------------------------------------------ script e comandi

    def script(self, text: str, cwds: List[Path], depth: int, strict: bool = True) -> None:
        if depth > MAX_DEPTH:
            self.deny("comando annidato troppo in profondità: non verificabile")
            return
        lx = Lexer(text)
        try:
            cmds = lx.parse()
        except Exception:
            if strict:
                self.deny("comando non analizzabile: non verificabile")
            return
        cwds = list(cwds)
        self.scan_tamper(text)
        self.funcs.update(a or b for a, b in FUNC_DEF_RE.findall(text))
        pipelines: Dict[int, List[Cmd]] = {}
        for cmd in cmds:
            pipelines.setdefault(cmd.pipeline, []).append(cmd)
        outer, outer_bodies = self.group_stdin, self.group_bodies
        files, bodies = self.shared_stdin(cmds)
        self.group_stdin, self.group_bodies = outer + files, outer_bodies + bodies
        try:
            # le sostituzioni di comando ereditano lo stdin della shell (`exec < f; x=$(bash)`, `{ …$(sh)…; } < f`)
            for sub in lx.subs:
                self.script(sub, cwds, depth + 1)
            for cmd in cmds:
                self.command(cmd, cwds, depth)
        finally:
            self.group_stdin, self.group_bodies = outer, outer_bodies
        for pl in pipelines.values():
            self.pipeline_checks(pl)

    def shared_stdin(self, cmds: List[Cmd]) -> Tuple[List[Arg], List[str]]:
        """File dati come stdin a un gruppo (`{ …; } < f`, `( … ) < f`, `done < f`) o alla shell stessa
        (`exec < f`, `exec 3< f`) o a una funzione definita nel comando (`f < f`): non si sa a quali comandi
        arrivano, quindi valgono per tutto lo script."""
        out: List[Arg] = []
        bodies: List[str] = []
        for cmd in cmds:
            head = [w.parts[0][1] if len(w.parts) == 1 and w.parts[0][0] == "lit" else None for w in cmd.words]
            if head and head not in (["}"], ["done"], ["fi"], ["esac"], ["exec"]) and head[0] not in self.funcs:
                continue
            for op, w in cmd.redirs:
                if op in ("<", "<>"):
                    out += self.expand(w)
            bodies += [self.expand_join(w) for w in cmd.stdin]
        return out, bodies

    def pipeline_checks(self, pl: List[Cmd]) -> None:
        for k, c in enumerate(pl):
            downloaded = any(x.download for x in pl[:k])
            if c.stdin_exec:
                if downloaded:
                    self.deny_tool("download eseguito da una shell o da un interprete, es. curl | sh")
                else:
                    self.deny(f"comandi passati da una pipe a `{c.name}`: il contenuto non è verificabile")
            elif downloaded and (c.writes or c.name in EXTRACTORS):
                self.deny_tool("download salvato o estratto su file")

    def command(self, cmd: Cmd, cwds: List[Path], depth: int) -> None:
        args: List[Arg] = []
        for w in cmd.words:
            args += self.expand(w)
        ctx = Ctx(cwds, depth, piped=cmd.pos > 0, cmd=cmd)
        for op, w in cmd.redirs:
            if op in ("<", "<>"):
                ctx.stdin_files += self.expand(w)
                if op == "<":
                    continue
            if op == "<&":
                for a in self.expand(w):
                    if not re.fullmatch(r"0|-|0-", a.text):
                        # stdin duplicato da un altro descrittore: è uno dei file aperti con `exec N< f`, se ci sono
                        ctx.stdin_files += self.group_stdin or [Arg(f"&{a.text}", dyn=True)]
                continue
            if op not in (">", ">>", ">|", "&>", "&>>", "<>", ">&"):
                continue
            for a in self.expand(w):
                if op == ">&" and re.fullmatch(r"\d+-?|-", a.text):
                    continue
                if a.text in SAFE_REDIRECT:
                    continue
                ctx.write_redir = True
                ctx.redir_targets.append(a)
                self.target(a, cwds)
        cmd.writes = ctx.write_redir
        ctx.stdin = [self.expand_join(w) for w in cmd.stdin]
        if not ctx.stdin and not ctx.stdin_files and not ctx.piped:
            ctx.stdin_files, ctx.stdin = list(self.group_stdin), list(self.group_bodies)
        self.run(args, ctx)

    def check_assigns(self, assigns: List[Tuple[str, str]], ctx: Ctx) -> None:
        for name, value in assigns:
            low = name.lower()
            if (low == "npm_config_global" and value.lower() not in ("", "false", "0")) \
                    or (low == "npm_config_location" and value.lower() == "global"):
                self.deny_tool(f"{name}={value}: installazione globale di pacchetti npm")
            if name.upper().startswith("TF_CLI_ARGS"):
                self.deny(f"variabile {name}: inietta opzioni nei comandi terraform/tofu e non è consentita")
            self.exec_env(name, value, ctx)
            if self.protect and PROTECTED_RE.search(f"{name}={value}"):
                self.deny(f"variabile {name}: tocca la configurazione o i file protetti di kynfra")

    def exec_env(self, name: str, value: Optional[str], ctx: Ctx) -> None:
        """Variabile che fa eseguire codice (EXEC_ENV); `value` None = valore non determinabile (`read`, …)."""
        kind = EXEC_ENV.get(name) or ("deny" if EXEC_ENV_RE.fullmatch(name) else None)
        if kind is None and GIT_TRACE_RE.fullmatch(name):
            if value is not None and value.lower() not in ("", "0", "1", "true", "false") \
                    and not re.fullmatch(r"[2-9]", value):
                self.target(Arg(value, "$" in value), ctx.cwds)
            return
        if kind is None:
            return
        self.env_tampered = True
        if value is not None:
            if kind == "cmd":
                self.script(value, ctx.cwds, ctx.depth + 1)
                return
            if kind == "path" and value.startswith("${PATH}"):
                return
            if kind == "file" and not re.search(r"[/.$~]", value):
                return
        what = "valore non determinabile" if value is None else "fa eseguire codice o caricare file non verificati"
        self.deny(f"variabile {name}: {what} (git, shell, interpreti, loader o make)")

    @staticmethod
    def sensitive_name(name: str) -> bool:
        """Variabile che cambia i programmi eseguiti o le loro opzioni (EXEC_ENV, PATH, TF_CLI_ARGS*)."""
        return name in EXEC_ENV or bool(EXEC_ENV_RE.fullmatch(name)) or name.upper().startswith("TF_CLI_ARGS")

    def scan_tamper(self, text: str) -> None:
        """Prima dell'analisi: il testo cambia PATH, `hash`, nameref o variabili di EXEC_ENV in un punto
        qualsiasi (anche dopo o in una funzione) → gli script del kit non sono più esenti."""
        names = [a or b for a, b in re.findall(r"(?<![\w$])([A-Za-z_]\w*)\+?=|\$\{([A-Za-z_]\w*):?=", text)]
        if any(self.sensitive_name(n) for n in names) or re.search(
                r"(?<![\w-])hash\b|(?<![\w-])(?:declare|typeset|local)\s+(?:[-+]\w+\s+)*-\w*n", text):
            self.env_tampered = True

    @staticmethod
    def exec_env_set(ctx: Ctx) -> bool:
        """Il comando riceve una variabile di EXEC_ENV: niente esenzione del kit."""
        return any(n in EXEC_ENV or EXEC_ENV_RE.fullmatch(n) for n in ctx.env)

    def builtin_names(self, name: str, args: List[Arg], ctx: Ctx) -> None:
        """Builtin che assegnano variabili senza `NOME=valore`: `read`, `printf -v`, `mapfile`/`readarray` (valore
        non determinabile) ed `export`/`declare` di un nome senza valore."""
        t = [a.text for a in args]
        names: List[str] = []
        if name == "read":
            i = 1
            while i < len(t) and t[i].startswith("-") and t[i] != "--":
                if t[i] in ("-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u"):
                    if t[i] == "-a" and i + 1 < len(t):
                        names.append(t[i + 1])
                    i += 2
                    continue
                if t[i].startswith("-a") and len(t[i]) > 2:
                    names.append(t[i][2:])
                i += 1
            names += t[i + (1 if i < len(t) and t[i] == "--" else 0):]
        elif name == "printf":
            for i, x in enumerate(t[1:], 1):
                if x == "-v" and i + 1 < len(t):
                    names.append(t[i + 1])
                elif x.startswith("-v") and len(x) > 2:
                    names.append(x[2:])
                if not x.startswith("-"):
                    break
        elif name in ("mapfile", "readarray"):
            names += [a.text for a in _opt_split(args[1:], {"-d", "-n", "-O", "-s", "-u", "-C", "-c"})][:1]
        elif name in ("export", "declare", "typeset", "local", "readonly"):
            if name in ("declare", "typeset", "local") and any(re.fullmatch(r"-\w*n\w*", x) for x in t[1:]):
                self.env_tampered = True
                self.deny(f"`{name} -n`: nameref, assegna variabili con un altro nome (PATH, EXEC_ENV, "
                          "TF_CLI_ARGS*) e non è verificabile")
            for x in t[1:]:
                if x.startswith(("-", "+")) or "=" in x:
                    continue
                if x.upper().startswith("TF_CLI_ARGS"):
                    self.deny(f"variabile {x}: inietta opzioni nei comandi terraform/tofu e non è consentita")
                elif EXEC_ENV.get(x) == "deny" or EXEC_ENV_RE.fullmatch(x):
                    self.exec_env(x, None, ctx)
            return
        for n in names:
            if n.upper().startswith("TF_CLI_ARGS"):
                self.deny(f"variabile {n}: inietta opzioni nei comandi terraform/tofu e non è consentita")
            self.exec_env(n, None, ctx)

    def set_var(self, name: str, value: str, dyn: bool) -> None:
        self.vars[name] = None if dyn else value

    def run(self, args: List[Arg], ctx: Ctx) -> None:
        args = list(args)
        while True:
            while args and args[0].text in RESERVED and not args[0].dyn:
                # `function f { …`: il nome della funzione non è un comando
                args = args[2:] if args[0].text == "function" else args[1:]
            if args and args[0].text in ("for", "select", "case") and not args[0].dyn:
                if args[0].text != "case" and len(args) > 1:
                    self.vars[args[1].text] = None
                return
            assigns: List[Tuple[str, str]] = []
            dyns: List[bool] = []
            while args and ASSIGN_RE.match(args[0].text):
                m = ASSIGN_RE.match(args[0].text)
                assigns.append((m.group(1), m.group(2)))
                dyns.append(args[0].dyn)
                args = args[1:]
                if not args:
                    # assegnazioni da sole: valgono per i comandi successivi della stessa riga
                    self.check_assigns(assigns, ctx)
                    for (name, value), dyn in zip(assigns, dyns):
                        self.set_var(name, value, dyn)
                    return
            self.check_assigns(assigns, ctx)
            ctx.env.update(dict(assigns))
            if not args:
                return
            new = self.unwrap(args, ctx)
            if new is None:
                return
            if new is args:
                break
            args = new
            if not args:
                return
        head = args[0]
        if head.dyn:
            self.deny(f"comando non determinabile ({head.text}): variabili o sostituzioni nel nome del comando "
                      "non si possono verificare")
            return
        if head.text in self.aliases and ctx.depth < MAX_DEPTH:
            alias = self.aliases.pop(head.text)
            try:
                self.script(alias + " " + " ".join(shlex.quote(a.text) for a in args[1:]), ctx.cwds, ctx.depth + 1)
            finally:
                self.aliases[head.text] = alias
            return
        name = norm_name(head.text)
        if ctx.cmd is not None and not ctx.cmd.name:
            ctx.cmd.name = name
        if ctx.xargs and (name in SHELLS or name in INTERPRETERS or name in WRITERS
                          or name in ("eval", "source", ".", "make", "npm", "pnpm", "yarn", "just", "task", "at",
                                      "batch", "crontab")):
            self.deny(f"`xargs {name}`: argomenti letti da stdin, comando non verificabile")
            return
        self.credential_reads(name, args, ctx)
        kind = self.dispatch(name, args, ctx)
        if kind in (KIT, DELEGATED):
            return
        ro = kind == RO and not ctx.write_redir
        if kind == RO and name in READONLY_CMDS:
            self.output_opts(args[1:], ctx.cwds, short_o=name == "tree")
        if not ro:
            if self.protect and self.mentions_protected(args[1:] + ctx.redir_targets, ctx.cwds):
                self.deny("il comando tocca file protetti di kynfra (configurazione, kit, hook o impostazioni "
                          "dell'agente): li modifica solo l'utente")
            if name not in NO_SCAN and name not in IAC_ARG_EXEMPT and name not in PRODUCERS:
                self.iac_args(name, args[1:], ctx.cwds)
            if any(TF_CLI_RE.search(a.text) for a in args[1:]):
                self.deny("variabile TF_CLI_ARGS*: inietta opzioni nei comandi terraform/tofu e non è consentita")

    def credential_file(self, a: Arg, cwds: List[Path]) -> Optional[str]:
        """Il percorso è un file di credenziali (~/.aws/credentials, cache SSO/CLI) o un .env non di esempio?"""
        if a.dyn and not a.globby:
            return None
        home = Path.home().resolve()
        for c in self.candidates(a, cwds):
            text = c.split("=", 1)[1] if c.startswith("-") and "=" in c else c
            if not text or text.startswith("-"):
                continue
            base = text.rstrip("/").rsplit("/", 1)[-1]
            if is_env_name(base) and base.lower() not in ENV_TEMPLATES:
                return text
            for p in self.resolve_all(text, cwds):
                try:
                    rel = p.relative_to(home).as_posix()
                except ValueError:
                    continue
                if any(rel == x.rstrip("/") or (x.endswith("/") and rel.startswith(x))
                       for x in CREDENTIAL_HOME_PATHS):
                    return text
        return None

    def credential_reads(self, name: str, args: List[Arg], ctx: Ctx) -> None:
        """Lettura di credenziali o .env da parte dell'agente (comandi che ne mostrano il contenuto, o `< file`)."""
        found = None
        if name in READERS:
            found = next((f for f in (self.credential_file(a, ctx.cwds) for a in args[1:]) if f), None)
        if found is None:
            found = next((f for f in (self.credential_file(a, ctx.cwds) for a in ctx.stdin_files) if f), None)
        if found:
            self.deny(f"lettura di {found}: credenziali e .env non si leggono dall'agente (finirebbero nella "
                      "conversazione); se serve un valore chiedilo all'utente")

    def output_opts(self, rest: List[Arg], cwds: List[Path], short_o: bool = False,
                    names: Tuple[str, ...] = ("--output",)) -> None:
        """Valori di `--output[=]` (e `-o`, se il comando lo usa per un file): sono scritture anche nei comandi
        di sola lettura (`git log --output=…`, `tree -o …`)."""
        for i, a in enumerate(rest):
            t = a.text
            name, eq, value = t.partition("=")
            if eq and name in names:
                self.target(Arg(value, a.dyn, a.globby), cwds)
            elif (t in names or (short_o and t == "-o")) and i + 1 < len(rest):
                self.target(rest[i + 1], cwds)
            elif short_o and t.startswith("-o") and len(t) > 2:
                self.target(Arg(t[2:], a.dyn, a.globby), cwds)

    def iac_args(self, name: str, rest: List[Arg], cwds: List[Path]) -> None:
        """Comando qualsiasi che riceve un file IaC come argomento: può scriverlo senza passare dai controlli."""
        for a in rest:
            t = a.text
            if a.dyn or not t:
                continue
            if t.startswith("-"):
                if "=" not in t:
                    continue
                t = t.split("=", 1)[1]
            for c in self.candidates(Arg(t, a.dyn, a.globby), cwds):
                if UNKNOWN_DIR in cwds and not os.path.isabs(os.path.expanduser(c)) \
                        and c.lower().endswith(rules.IAC_EXT):
                    self.deny(f"`{name}` riceve il file IaC {c} in una cartella non determinabile: usa Write/Edit")
                    return
                for p in self.resolve_all(c, cwds):
                    rel = rules.rel_to_project(str(p), self.proj)
                    irel = rules.infra_rel(rel, self.cfg) if rel is not None else None
                    if irel is not None and rules.is_iac_file(irel):
                        self.deny(f"`{name}` riceve il file IaC {rel} come argomento e può scriverlo senza passare "
                                  "dai controlli: i file IaC si scrivono con Write/Edit")
                        return

    def mentions_protected(self, args: List[Arg], cwds: List[Path]) -> bool:
        for a in args:
            for t in self.candidates(a, cwds):
                if PROTECTED_RE.search(t) or rules.GIT_MODULE_RE.search(t.lower().rstrip("/")):
                    return True
        return False

    # ------------------------------------------------------------ wrapper

    def unwrap(self, args: List[Arg], ctx: Ctx) -> Optional[List[Arg]]:
        """Toglie i comandi che ne lanciano un altro. Restituisce gli argomenti del comando interno, `args` se non
        c'è nulla da togliere, None se il comando è già stato gestito."""
        if args[0].dyn:
            return args
        n = norm_name(args[0].text)
        t = [a.text for a in args]
        L = len(t)

        def skip_opts(i: int, value_opts: Set[str] = frozenset(), stop_at_assign: bool = False) -> int:
            while i < L:
                x = t[i]
                if x == "--":
                    return i + 1
                if stop_at_assign and ASSIGN_RE.match(x):
                    return i
                if x.startswith("-") and len(x) > 1:
                    i += 2 if x in value_opts else 1
                    continue
                return i
            return i

        if n == "env":
            i = 1
            while i < L:
                x = t[i]
                if x in ("-S", "--split-string") or (x.startswith("-S") and len(x) > 2) \
                        or x.startswith("--split-string="):
                    if x in ("-S", "--split-string"):
                        s, nxt = (t[i + 1] if i + 1 < L else ""), i + 2
                    else:
                        s, nxt = (x[2:] if x.startswith("-S") else x.split("=", 1)[1]), i + 1
                    return self.words_of(s) + args[nxt:]
                if x in ("-u", "--unset", "-C", "--chdir", "-P"):
                    i += 2
                    continue
                if x == "--":
                    i += 1
                    break
                if x.startswith("-"):
                    i += 1
                    continue
                break
            return args[i:] or None
        if n == "command":
            i = 1
            while i < L and t[i].startswith("-"):
                if any(ch in t[i] for ch in "vV"):
                    return None
                i += 1
            return args[i:] or None
        if n == "exec":
            i = 1
            while i < L and t[i].startswith("-"):
                i += 2 if t[i] == "-a" else 1
            return args[i:] or None
        if n in ("nohup", "builtin", "unbuffer", "chronic", "noglob", "nocorrect"):
            return args[1:] or None
        if n == "time":
            i = 1
            while i < L and t[i].startswith("-"):
                if t[i] in ("-o", "--output") and i + 1 < L:
                    self.target(args[i + 1], ctx.cwds)
                    i += 2
                    continue
                i += 1
            return args[i:] or None
        if n in ("sudo", "doas"):
            i = skip_opts(1, {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R", "--user", "--group",
                              "--host", "--prompt", "--chdir", "--role", "--type", "--other-user", "--close-from",
                              "--command-timeout"}, stop_at_assign=True)
            return args[i:] or None
        if n == "nice":
            return args[skip_opts(1, {"-n", "--adjustment"}):] or None
        if n == "ionice":
            return args[skip_opts(1, {"-c", "-n", "-p", "-t", "--class", "--classdata"}):] or None
        if n in ("timeout", "gtimeout"):
            i = skip_opts(1, {"-s", "-k", "--signal", "--kill-after"})
            return args[i + 1:] or None
        if n == "stdbuf":
            return args[skip_opts(1, {"-i", "-o", "-e", "--input", "--output", "--error"}):] or None
        if n == "caffeinate":
            return args[skip_opts(1, {"-t", "-w"}):] or None
        if n == "xargs":
            i = skip_opts(1, {"-I", "-L", "-n", "-P", "-s", "-E", "-d", "-a", "-R", "-S", "--max-args",
                              "--max-procs", "--delimiter", "--arg-file", "--replace", "--max-lines", "--eof"})
            ctx.xargs = True
            return args[i:] or None
        if n == "watch":
            i = skip_opts(1, {"-n", "--interval", "-d", "--differences", "-q", "--equexit"})
            self.script(" ".join(t[i:]), ctx.cwds, ctx.depth + 1)
            return None
        raw = args[0].text.rstrip("/").rsplit("/", 1)[-1].lower()
        if n in ("pnpm", "yarn") and self.has_dlx(t):
            self.deny_tool(f"{n} dlx: scarica ed esegue un pacchetto")
            return None
        if n == "gem" and L > 1 and "exec" in t[1:3]:
            self.deny_tool("gem exec: scarica ed esegue un pacchetto")
            return None
        if raw in ("bunx", "pnpx") or (n in ("pnpm", "yarn") and L > 1 and t[1] == "dlx") \
                or (n == "bun" and L > 1 and t[1] == "x"):
            self.deny_tool(f"{raw if raw in ('bunx', 'pnpx') else n + ' ' + t[1]}: scarica ed esegue un pacchetto")
            return None
        if n == "npx" or (n == "npm" and L > 1 and t[1] in ("exec", "x")) \
                or (n in ("pnpm", "yarn") and L > 1 and t[1] == "exec"):
            local_only = n in ("pnpm", "yarn")
            label = "npx" if n == "npx" else f"{n} {t[1]}"
            i = 1 if n == "npx" else 2
            packages: List[str] = []
            while i < L and t[i].startswith("-"):
                if t[i] in ("-c", "--call") and i + 1 < L:
                    if not local_only and packages:
                        self.npx_packages(label, packages, ctx)
                    self.script(t[i + 1], ctx.cwds, ctx.depth + 1)
                    return None
                if t[i] == "--":
                    i += 1
                    break
                if t[i] in ("-y", "--yes") or t[i].startswith("--yes="):
                    if not local_only and t[i] != "--yes=false":
                        self.deny_tool(f"{label} {t[i]}: scarica ed esegue pacchetti senza chiedere")
                if t[i] in ("-p", "--package") and i + 1 < L:
                    packages.append(t[i + 1])
                    i += 2
                    continue
                if t[i].startswith("--package="):
                    packages.append(t[i].split("=", 1)[1])
                i += 1
            if not local_only:
                if not packages and i < L:
                    packages.append(t[i])
                self.npx_packages(label, packages, ctx, [a.dyn for a in args])
            return args[i:] or None
        if n in ("uv", "poetry", "pipenv", "rye", "pdm", "hatch") and L > 1 and t[1] == "run":
            if n == "uv" and any(re.match(r"--with(?:-requirements|-editable)?(?:=|$)", x) for x in t[2:]):
                self.deny_tool("uv run --with: scarica pacchetti non dichiarati nel progetto")
            i = skip_opts(2, {"--with", "--python", "-p", "--project", "--directory", "--package", "--extra",
                              "--group", "--env-file", "--index", "--with-requirements", "--from", "-e", "--env"})
            rest = args[i:]
            if rest and rest[0].text.endswith(".py"):
                rest = [Arg("python")] + rest
            return rest or None
        if n == "aws-vault" and L > 1 and t[1] == "exec":
            if "--" in t:
                return args[t.index("--") + 1:] or None
            i = skip_opts(2)
            return args[i + 1:] or None
        if n == "direnv" and L > 2 and t[1] == "exec":
            return args[3:] or None
        return args

    def npx_packages(self, label: str, packages: List[str], ctx: Ctx, dyns: Optional[List[bool]] = None) -> None:
        """`npx`/`npm exec` scaricano il pacchetto se non è installato: consentiti solo i pacchetti dichiarati nel
        package.json del progetto o già presenti in node_modules/.bin."""
        if dyns and any(dyns):
            self.deny_tool(f"{label} con pacchetto non determinabile")
            return
        manifests = [m for m in (self.find_upward(c, ("package.json",)) for c in ctx.cwds if c != UNKNOWN_DIR) if m]
        deps: Set[str] = set()
        for m in manifests:
            try:
                data = json.loads(_read_text(m) or "{}")
            except ValueError:
                continue
            for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                section = data.get(key) if isinstance(data, dict) else None
                if isinstance(section, dict):
                    deps.update(section)
        for pkg in packages:
            local = (pkg not in ("", ".") and "@" not in pkg[1:]
                     and (pkg in deps or any((m.parent / "node_modules" / ".bin" / pkg).is_file()
                                             for m in manifests)))
            if not local:
                self.deny_tool(f"{label} {pkg}: pacchetto non dichiarato nel package.json del progetto, verrebbe "
                               "scaricato ed eseguito")

    # ------------------------------------------------------------ smistamento

    def dispatch(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        if name == "hash":
            if any(re.match(r"-[^-]*p", a.text) or a.dyn for a in args[1:]):
                self.env_tampered = True
                self.deny("`hash -p`: cambia il programma eseguito per un nome di comando, non verificabile")
            return RO
        if name in ("read", "printf", "mapfile", "readarray", "export", "declare", "typeset", "local", "readonly"):
            self.builtin_names(name, args, ctx)
        if name in ("cd", "pushd"):
            self.cd(args, ctx)
            return RO
        if name in ("terraform", "tofu", "terragrunt"):
            return self.terraform(name, args, ctx)
        if name == "aws":
            return self.aws(args, ctx)
        if name == "kubectl":
            return self.kubectl(args, ctx)
        if name == "helm":
            return self.helm(args, ctx)
        if name in CLOUD_DENIED:
            if len(args) == 2 and args[1].text in VERSION_HELP:
                return RO
            self.deny(f"`{name}`: CLI cloud non consentita all'agente (modifica account o fa deploy); "
                      "la usa il DevOps")
            return RW
        if name == "busybox" and len(args) > 1:
            self.run(args[1:], ctx)
            return DELEGATED
        if name in SHELLS:
            return self.shell(name, args, ctx)
        if name == "eval":
            self.script(" ".join(a.text for a in args[1:]), ctx.cwds, ctx.depth + 1)
            return DELEGATED
        if name in ("source", "."):
            if len(args) < 2:
                return RO
            return self.exec_file(args[1], args[2:], ctx, lang="sh")
        if name in ("export", "declare", "typeset", "local", "readonly"):
            assigns = []
            for a in args[1:]:
                m = ASSIGN_RE.match(a.text)
                if m:
                    assigns.append((m.group(1), m.group(2)))
                    self.set_var(m.group(1), m.group(2), a.dyn)
            self.check_assigns(assigns, ctx)
            return DELEGATED
        if name == "alias":
            for a in args[1:]:
                m = re.match(r"^([^=\s]+)=(.*)$", a.text, re.S)
                if m:
                    self.aliases[m.group(1)] = m.group(2)
            return DELEGATED
        if name == "unalias":
            for a in args[1:]:
                self.aliases.pop(a.text, None)
            return DELEGATED
        if name == "python":
            return self.python(args, ctx)
        if name in ("node", "deno", "bun", "ts-node", "tsx"):
            return self.node(name, args, ctx)
        if name in ("ruby", "perl", "php", "lua"):
            return self.ruby_perl(name, args, ctx)
        if name in ("awk", "gawk", "mawk", "nawk"):
            return self.awk(args, ctx)
        if name == "curl":
            return self.curl(args, ctx)
        if name == "wget":
            return self.wget(args, ctx)
        if name in ALWAYS_INSTALL:
            if len(args) == 2 and args[1].text in VERSION_HELP:
                return RO
            self.deny_tool(name)
            return RW
        if name in PKG_MANAGERS:
            return self.pkg_manager(name, args, ctx)
        if name in ("nix", "nix-shell", "dpkg", "rpm", "installer"):
            return self.system_installer(name, args, ctx)
        if name in ("pip", "pipx", "uv", "cargo", "gem", "go"):
            return self.lang_installer(name, args, ctx)
        if name in ("npm", "pnpm", "yarn"):
            return self.node_pm(name, args, ctx)
        if name == "make":
            return self.make(args, ctx)
        if name in ("at", "batch"):
            return self.at(name, args, ctx)
        if name == "crontab":
            if all(a.text in ("-l", "-u") or a.text.startswith("-u") for a in args[1:]) \
                    and any(a.text == "-l" for a in args[1:]):
                return RO
            self.deny("`crontab`: installa o cambia job pianificati il cui contenuto non è verificabile "
                      "(consentito solo `crontab -l`)")
            return RW
        if name == "just":
            return self.just(args, ctx)
        if name == "task":
            return self.task(args, ctx)
        if name == "git":
            return self.git(args, ctx)
        if name == "gh":
            pos = _opt_split(args[1:], {"-R", "--repo"})
            pair = tuple(a.text for a in pos[:2])
            if pair in (("release", "download"), ("extension", "install"), ("ext", "install")):
                self.deny_tool("gh " + " ".join(pair))
            return RW
        if name == "find":
            return self.find(args, ctx)
        if name == "link":
            self.links(name, args[1:], ctx)
        if name in ("patch",):
            self.deny("git apply/patch scrivono file senza passare dai controlli: applica le modifiche con Write/Edit")
            return RW
        if (name == "install.sh" or "/" in args[0].text) and name not in WRITERS and name not in READONLY_CMDS \
                and name not in PRODUCERS:
            return self.exec_file(args[0], args[1:], ctx)
        if name in PRODUCERS:
            self.producers(name, args, ctx)
            return RW
        if name in WRITERS:
            self.writers(name, args, ctx)
            return RW
        if name == "rg":
            self.rg(args, ctx)
        if name in READONLY_CMDS:
            return RO
        if name not in NO_SCAN:
            self.generic(args, ctx)
        return RW

    def generic(self, args: List[Arg], ctx: Ctx) -> None:
        """Comando sconosciuto (docker, ssh, trap, flock…): analizza i comandi che porta come argomenti."""
        for i in range(1, len(args)):
            a = args[i]
            if a.dyn:
                continue
            # il nome si confronta senza maiuscole (macOS non le distingue), tranne quando la parola è
            # probabilmente il valore di un'opzione (`docker login --username AWS`, `-u AWS`)
            prev = args[i - 1].text if i > 1 else ""
            opt_value = (prev.startswith("--") and prev != "--" and "=" not in prev) \
                or re.fullmatch(r"-[A-Za-z]", prev) is not None
            if norm_name(a.text, lower=False) in SCAN_NAMES or (not opt_value and norm_name(a.text) in SCAN_NAMES):
                self.run(args[i:], ctx.nested())
            elif re.search(r"\s", a.text.strip()):
                self.script(a.text, ctx.cwds, ctx.depth + 1, strict=False)

    def program_value(self, value: Optional[Arg], label: str, ctx: Ctx) -> None:
        """Valore di un'opzione che fa lanciare un programma (`tar -I`, `rg --pre`, `git difftool -x`…): si
        analizza come comando; se è uno script che non si può leggere o un programma sconosciuto si rifiuta."""
        if value is None:
            return
        if value.dyn:
            self.deny(f"`{label}`: programma non determinabile (variabile o sostituzione)")
            return
        words = self.words_of(value.text)
        if not words:
            return
        head = words[0]
        if head.dyn:
            self.deny(f"`{label}`: programma non determinabile ({head.text})")
            return
        name = norm_name(head.text)
        if "/" in head.text and not (SYSTEM_BIN_RE.match(head.text) and name in KNOWN_PROGRAMS):
            if not any(_read_text(p) is not None for p in self.resolve_all(head.text, ctx.cwds)):
                self.deny(f"`{label} {head.text}`: script che non si può leggere né verificare")
                return
        elif "/" not in head.text and name not in KNOWN_PROGRAMS:
            self.deny(f"`{label} {head.text}`: lancia un programma sconosciuto che non si può verificare")
            return
        self.script(value.text, ctx.cwds, ctx.depth + 1)

    def rg(self, args: List[Arg], ctx: Ctx) -> None:
        """`rg --pre PROG`: ripgrep lancia PROG su ogni file cercato."""
        t = [a.text for a in args]
        for i in range(1, len(t)):
            if t[i] == "--":
                break
            lo = long_opt(t[i], ("pre",), abbrev=False)
            if lo:
                val = Arg(lo[1], args[i].dyn) if lo[1] is not None else (args[i + 1] if i + 1 < len(t) else None)
                self.program_value(val, "rg --pre", ctx)

    def tar_programs(self, name: str, rest: List[Arg], ctx: Ctx) -> None:
        """Opzioni di tar che lanciano programmi: -I/--use-compress-program, -F/--info-script, --to-command,
        --checkpoint-action=exec=…, --rsh-command, --rmt-command (anche nella forma vecchia `tar cIf prog …`)."""
        t = [a.text for a in rest]
        j = 0
        if t and not t[0].startswith("-"):
            k = 1
            for ch in t[0]:
                if ch in TAR_SHORT_VALUE and k < len(t):
                    if ch in "IF":
                        self.program_value(rest[k], f"{name} {ch}", ctx)
                    k += 1
            j = k
        while j < len(t):
            x = t[j]
            if x == "--":
                break
            lo = long_opt(x, TAR_PROGRAM_OPTS, exact={"checkpoint"})
            if lo:
                opt, val = lo
                if val is not None:
                    value: Optional[Arg] = Arg(val, rest[j].dyn)
                else:
                    value = rest[j + 1] if j + 1 < len(t) else None
                    j += 1
                if opt == "checkpoint-action":
                    if value is not None and value.dyn:
                        self.program_value(value, f"{name} --{opt}", ctx)
                    elif value is not None and value.text.startswith("exec="):
                        self.program_value(Arg(value.text[5:]), f"{name} --{opt}=exec", ctx)
                else:
                    self.program_value(value, f"{name} --{opt}", ctx)
            elif x.startswith("-") and not x.startswith("--"):
                for pos, ch in enumerate(x[1:], 1):
                    if ch in TAR_SHORT_VALUE:
                        if x[pos + 1:]:
                            value = Arg(x[pos + 1:], rest[j].dyn)
                        else:
                            value = rest[j + 1] if j + 1 < len(t) else None
                            j += 1
                        if ch in "IF":
                            self.program_value(value, f"{name} -{ch}", ctx)
                        break
            j += 1

    def cd(self, args: List[Arg], ctx: Ctx) -> None:
        pos = [a for a in args[1:] if not a.text.startswith("-") or a.text == "-"]
        if pos and pos[0].text == "-":
            return
        if pos and pos[0].dyn:
            new = [UNKNOWN_DIR]
        elif not pos:
            new = [Path.home()]
        else:
            new = self.resolve_all(pos[0].text, ctx.cwds)
        for p in new:
            if p not in ctx.cwds and len(ctx.cwds) < 32:
                ctx.cwds.append(p)

    # ------------------------------------------------------------ terraform / tofu

    def terraform(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        rest = args[1:]
        i = 0
        while i < len(rest) and rest[i].text.startswith("-"):
            if rest[i].text in ("-version", "--version", "-v", "-help", "--help", "-h"):
                return RO
            i += 1
        if i >= len(rest):
            if ctx.xargs:
                self.deny(f"`xargs {name}`: sottocomando letto da stdin, non verificabile")
            return RO
        sub_arg = rest[i]
        sub = sub_arg.text
        opts = rest[i + 1:]
        label = f"`{name} {sub}`"
        if sub_arg.dyn:
            self.deny(f"{label}: sottocomando non determinabile (variabile o sostituzione)")
            return RW
        if name == "terragrunt":
            return self.terragrunt(sub, opts)
        if ctx.xargs and sub not in ("fmt", "validate", "version"):
            self.deny(f"`xargs {name} {sub}`: argomenti letti da stdin, non verificabile")
            return RW
        pos = [a for a in opts if not a.text.startswith("-")]
        first = pos[0].text if pos else ""
        if sub in TF_READONLY:
            return RW
        if sub == "providers":
            if first in ("lock", "mirror"):
                self.deny(f"{label} {first}: scarica provider o riscrive .terraform.lock.hcl; lo fa "
                          "`terraform init -backend=false` nello stop gate o l'utente")
            return RW
        if sub == "output":
            if not any(a.text in ("-json", "--json") for a in opts):
                self.deny(f"{label}: consentito solo `{name} output -json`")
            return RW
        if sub == "init":
            backend = None
            for a in opts:
                m = re.fullmatch(r"--?backend=(.*)", a.text)
                if m:
                    backend = m.group(1).strip().lower()
            if any(a.dyn for a in opts):
                self.deny(f"{label}: opzioni non determinabili (variabili o sostituzioni)")
            elif backend not in ("false", "0", "f"):
                self.deny(f"{label} con backend reale: l'agente può lanciare solo `{name} init -backend=false`")
            elif any(re.match(r"--?from-module", a.text) for a in opts):
                self.deny(f"{label} -from-module: scrive file IaC senza passare dalle regole")
            return RW
        if sub == "state":
            if first not in ("list", "show") or pos[0].dyn:
                self.deny(f"{label} {first}".rstrip() + ": consentiti solo `state list` e `state show`")
            return RW
        if sub == "workspace":
            if first in ("list", "show") or (first == "select" and not any(
                    a.text.startswith(("-or-create", "--or-create")) and not a.text.endswith("=false") for a in opts)):
                return RW
            self.deny(f"{label} {first}".rstrip() + ": consentiti solo `workspace list|show|select`")
            return RW
        if sub in TF_DENIED:
            why = "richiede credenziali: lo lancia il DevOps" if sub == "plan" else \
                "modifica lo stato o l'account cloud: lo esegue il DevOps (pipeline o utente), non l'agente"
            self.deny(f"{label}: {why}")
            return RW
        self.deny(f"{label}: sottocomando non consentito all'agente (consentiti fmt, validate, version, providers, "
                  "graph, show, output -json, state list|show, workspace list|show|select, init -backend=false)")
        return RW

    def terragrunt(self, sub: str, opts: List[Arg]) -> str:
        first = next((a.text for a in opts if not a.text.startswith("-")), "")
        if sub in ("hclfmt", "fmt", "version", "help"):
            return RW
        if sub == "hcl" and first in ("fmt", "format", "validate"):
            return RW
        self.deny(f"`terragrunt {sub}`: terragrunt inizializza il backend reale e può creare risorse "
                  "(anche con validate/run-all); consentiti solo hclfmt e hcl fmt|validate")
        return RW

    # ------------------------------------------------------------ CLI cloud

    def aws(self, args: List[Arg], ctx: Ctx) -> str:
        pos = _opt_split(args[1:], AWS_VALUE_OPTS)[:2]
        if not pos or pos[0].text == "help":
            if ctx.xargs:
                self.deny("`xargs aws`: operazione letta da stdin, non verificabile")
            return RO
        if any(a.dyn for a in pos):
            self.deny("`aws`: servizio o operazione non determinabili (variabile o sostituzione)")
            return RW
        if len(pos) < 2:
            self.deny(f"`aws {pos[0].text}`: operazione mancante o alias della CLI, non verificabile")
            return RW
        svc, op = pos[0].text, pos[1].text
        if (svc, op) in AWS_SECRET_OPS:
            flag = AWS_SECRET_OPS[(svc, op)]
            if flag is None or any(a.text == flag or a.text.startswith(flag + "=")
                                   or _abbrev_of(a.text, flag) for a in args[2:]):
                self.deny(f"`aws {svc} {op}`" + (f" {flag}" if flag else "") + ": restituisce segreti o credenziali "
                          "in chiaro; l'agente non li legge (li usa il DevOps o la pipeline)")
                return RW
        if svc == "ssm" and op in ("get-parameter", "get-parameters", "get-parameters-by-path",
                                   "get-parameter-history") \
                and any(a.text.startswith(("--cli-input-json", "--cli-input-yaml")) for a in args[2:]):
            self.deny(f"`aws ssm {op} --cli-input-*`: l'input da file può includere WithDecryption e restituire "
                      "segreti in chiaro")
            return RW
        if (svc, op) == ("s3api", "get-object"):
            self.aws_outfile(args[1:], ctx)
        if op == "help" or op.startswith(("get-", "describe-", "list-")) or (svc, op) == ("s3", "ls") \
                or (svc == "s3api" and op.startswith("head-")):
            return RO
        self.deny(f"`aws {svc} {op}`: operazione che può modificare l'account cloud (consentite solo get-*, "
                  "describe-*, list-*, sts get-caller-identity, s3 ls, s3api head-*)")
        return RW

    def aws_outfile(self, rest: List[Arg], ctx: Ctx) -> None:
        """`aws s3api get-object … <outfile>`: l'unico posizionale dopo servizio e operazione è il file scritto."""
        flags = {"--debug", "--no-verify-ssl", "--no-paginate", "--no-sign-request", "--no-cli-pager",
                 "--cli-auto-prompt", "--no-cli-auto-prompt"}
        pos: List[Arg] = []
        i = 0
        while i < len(rest):
            t = rest[i].text
            if t.startswith("--"):
                i += 1 if ("=" in t or t in flags) else 2
                continue
            pos.append(rest[i])
            i += 1
        for a in pos[2:]:
            self.target(a, ctx.cwds)

    def kubectl(self, args: List[Arg], ctx: Ctx) -> str:
        pos = _opt_split(args[1:], KUBECTL_VALUE_OPTS)
        if not pos:
            if ctx.xargs:
                self.deny("`xargs kubectl`: sottocomando letto da stdin, non verificabile")
            return RO
        sub = pos[0].text
        second = pos[1].text if len(pos) > 1 else ""
        if pos[0].dyn:
            self.deny("`kubectl`: sottocomando non determinabile")
        elif sub == "get" and self.kubectl_secret_dump(args[1:], pos[1:]):
            self.deny("`kubectl get secret`: con -o yaml|json|jsonpath|template stampa i segreti in chiaro; "
                      "l'agente non li legge")
        elif sub == "get" and any(a.text == "--raw" or a.text.startswith("--raw=") for a in args[1:]):
            self.deny("`kubectl get --raw`: legge endpoint API arbitrari (anche /secrets); l'agente non li legge")
        elif sub == "config" and second == "view" and any(
                a.text.lower().startswith(("--raw", "--flatten")) for a in args[1:]):
            self.deny("`kubectl config view --raw|--flatten`: stampa token e chiavi del kubeconfig; l'agente non li legge")
        elif sub in ("get", "describe", "explain", "version", "help") or (
                sub == "config" and second in ("view", "get-contexts") and not pos[1].dyn):
            return RO
        else:
            label = f"kubectl {sub} {second}".rstrip()
            self.deny(f"`{label}`: può modificare il cluster (consentiti get, describe, explain, version, "
                      "config view|get-contexts)")
        return RW

    @staticmethod
    def has_dlx(t: List[str]) -> bool:
        """`dlx` come sottocomando di pnpm/yarn, anche dopo opzioni (`pnpm -s dlx`, `pnpm --package=x dlx`)."""
        for i in range(1, len(t)):
            if t[i] == "dlx":
                return True
            if not t[i].startswith("-") and not t[i - 1].startswith("-"):
                return False  # primo sottocomando reale (run, exec, …)
        return False

    @staticmethod
    def kubectl_secret_dump(rest: List[Arg], resources: List[Arg]) -> bool:
        """`kubectl get` di risorse secret con un formato di output che include i dati (tutti tranne wide/name)."""
        def is_secret(a: Arg) -> bool:
            return a.dyn or any(part.split("/", 1)[0].split(".", 1)[0].lower() in KUBECTL_SECRET_RESOURCES
                                for part in a.text.split(","))
        if not any(is_secret(a) for a in resources):
            return False
        for i, a in enumerate(rest):
            t = a.text
            if t in ("-o", "--output"):
                fmt = rest[i + 1].text if i + 1 < len(rest) else ""
            elif t.startswith(("--output=", "-o=")):
                fmt = t.split("=", 1)[1]
            elif t.startswith("-o"):
                fmt = t[2:]
            elif t == "--template" or t.startswith("--template="):
                return True
            else:
                continue
            if a.dyn or fmt.split("=", 1)[0].lower() not in KUBECTL_SAFE_OUTPUT:
                return True
        return False

    def helm(self, args: List[Arg], ctx: Ctx) -> str:
        pos = _opt_split(args[1:], HELM_VALUE_OPTS)
        if not pos:
            if ctx.xargs:
                self.deny("`xargs helm`: sottocomando letto da stdin, non verificabile")
            return RO
        sub = pos[0].text
        if not pos[0].dyn and sub in ("template", "lint", "show", "version", "list", "ls", "status", "help"):
            if any(a.text.startswith("--post-renderer") for a in args):
                self.deny("`helm --post-renderer`: esegue un programma arbitrario")
            for i, a in enumerate(args):
                if a.text == "--output-dir" and i + 1 < len(args):
                    self.target(args[i + 1], ctx.cwds, extract=True)
                elif a.text.startswith("--output-dir="):
                    self.target(Arg(a.text.split("=", 1)[1], a.dyn, a.globby), ctx.cwds, extract=True)
            return RO
        self.deny(f"`helm {sub}`: può modificare il cluster (consentiti template, lint, show, version, list, status)")
        return RW

    # ------------------------------------------------------------ shell e interpreti

    def shell(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        i, has_c, from_stdin = 1, False, False
        while i < len(args):
            x = args[i].text
            if x in ("--", "-"):
                i += 1
                break
            if x in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
                i += 2
                continue
            if x.startswith("--"):
                i += 1
                continue
            if x[:1] in "-+" and len(x) > 1:
                has_c = has_c or (x[0] == "-" and "c" in x[1:])
                from_stdin = from_stdin or "s" in x[1:]
                i += 1
                continue
            break
        rest = args[i:]
        if has_c:
            if not rest:
                return RO
            if rest[0].dyn:
                self.deny(f"`{name} -c`: stringa di comando non determinabile (variabile o sostituzione)")
            self.script(rest[0].text, ctx.cwds, ctx.depth + 1)
            return DELEGATED
        if rest and not from_stdin:
            return self.exec_file(rest[0], rest[1:], ctx, lang="sh")
        return self.stdin_code(name, ctx, lang="sh")

    def stdin_code(self, name: str, ctx: Ctx, lang: str, required: bool = False) -> str:
        """Interprete senza script: legge il codice da heredoc/herestring, da `< file` o dalla pipe.

        `required`: lo script deve arrivare dallo stdin (`/dev/stdin`, `/dev/fd/N`, `at`): se non si sa da dove
        arriva il testo, il comando si rifiuta."""
        if ctx.stdin:
            for body in ctx.stdin:
                if lang == "sh":
                    self.script(body, ctx.cwds, ctx.depth + 1)
                else:
                    self.check_code(body, f"codice passato a {name}", lang)
            return DELEGATED
        if ctx.stdin_files:
            files, ctx = ctx.stdin_files, replace(ctx, stdin_files=[])
            for f in files:
                if f.dyn:
                    self.deny(f"`{name} < {f.text}`: file non determinabile, il contenuto non è verificabile")
                    continue
                self.run_file(f.text, ctx, lang)
            return DELEGATED
        if ctx.piped and ctx.cmd is not None:
            ctx.cmd.stdin_exec = True
        elif required:
            self.deny(f"`{name}`: script letto dallo stdin o da un descrittore di cui non si conosce il contenuto, "
                      "non verificabile")
        return DELEGATED

    def exec_file(self, path: Arg, rest: List[Arg], ctx: Ctx, lang: Optional[str] = None) -> str:
        """Esecuzione di uno script: il kit è consentito, gli altri script si leggono e si controllano."""
        flags = [a.text for a in rest]
        if norm_name(path.text) == "install.sh" and any(re.match(r"--(?:force|uninstall)\b", f) for f in flags):
            self.deny("install.sh con --force o --uninstall lo esegue solo l'utente")
            return KIT
        if path.dyn:
            self.deny(f"script non determinabile ({path.text}): variabili, sostituzioni o `<(…)` non si possono "
                      "verificare")
            if re.search(r"\b(?:curl|wget)\b", path.text):
                self.deny_tool("script scaricato ed eseguito")
            return RW
        if STDIN_PATH_RE.fullmatch(path.text):
            return self.stdin_code(path.text, ctx, lang or "sh", required=True)
        if path.text == "/dev/null":
            return DELEGATED
        if path.text.startswith(("/dev/", "/proc/")):
            self.deny(f"script letto da {path.text}: contenuto non verificabile")
            return RW
        resolved = [] if self.exec_env_set(ctx) else self.resolve_all(path.text, ctx.cwds)
        for p in resolved:
            sp = str(p)
            if sp in self.kit_install or (sp in self.kit_setup and len(flags) <= 1
                                          and all(f in ("local", "project", "user") for f in flags)):
                return KIT
        self.run_file(path.text, ctx, lang)
        return RW

    def run_file(self, path_text: str, ctx: Ctx, lang: Optional[str] = None) -> None:
        if STDIN_PATH_RE.fullmatch(path_text):
            self.stdin_code(path_text, ctx, lang or "sh", required=True)
            return
        for p in self.resolve_all(path_text, ctx.cwds):
            self.executed.add(str(p))
        for p in self.resolve_all(path_text, ctx.cwds):
            text = _read_text(p)
            if text is None:
                continue
            first = text.split("\n", 1)[0]
            shebang = first[2:] if first.startswith("#!") else ""
            code_lang = lang
            if code_lang in (None, "sh") and shebang:
                for key in ("python", "node", "deno", "bun", "ruby", "perl", "php", "lua"):
                    if re.search(rf"\b{key}", shebang):
                        code_lang = key
                        break
            if code_lang in (None, "sh"):
                self.script(text, ctx.cwds, ctx.depth + 1)
            else:
                self.check_code(text, f"script {path_text}", code_lang)
            return

    def check_code(self, code: str, origin: str, lang: str = "python") -> None:
        spawn = bool(SPAWN_RE.search(code)) \
            or (lang in ("ruby", "perl", "php", "lua") and bool(TICK_RE.search(code) or LOOSE_SPAWN_RE.search(code))) \
            or (lang == "awk" and bool(AWK_SPAWN_RE.search(code)))
        write = bool(WRITE_RE.search(code)) or (lang == "awk" and bool(AWK_WRITE_RE.search(code)))
        if SDK_RE.search(code):
            self.deny(f"{origin}: usa gli SDK cloud (boto3, @aws-sdk, azure, google-cloud…): l'agente non tocca "
                      "gli account cloud")
        if spawn and CLOUD_WORD_RE.search(code):
            self.deny(f"{origin}: lancia terraform/tofu o CLI cloud da codice, non verificabile")
        if spawn and INSTALL_WORD_RE.search(code):
            self.deny_tool(f"{origin} lancia download o gestori di pacchetti")
        if SAVE_DOWNLOAD_RE.search(code) or (NET_RE.search(code) and (write or spawn)):
            self.deny_tool(f"{origin} scarica file")
        root = self.cfg.get("infra_root", ".")
        if write and (IAC_MENTION_RE.search(code) or PROTECTED_RE.search(code)
                      or (root not in ("", ".") and root + "/" in code)):
            self.deny(f"{origin}: scrive file IaC, .env o protetti; il codice IaC si scrive con Write/Edit")
        if OBFUSCATED_RE.search(code):
            self.deny(f"{origin}: esegue codice offuscato (decodifica + exec/eval), non verificabile")

    def python(self, args: List[Arg], ctx: Ctx) -> str:
        i, opts = 1, []
        while i < len(args):
            x = args[i].text
            if x == "-":
                return self.stdin_code("python", ctx, "python")
            if x == "--":
                i += 1
                break
            if x.startswith("--"):
                opts.append(x)
                i += 1
                continue
            if x.startswith("-") and len(x) > 1:
                for j in range(1, len(x)):
                    ch = x[j]
                    if ch in "cm":
                        value = x[j + 1:]
                        nxt = i + 1
                        if not value:
                            value = args[i + 1].text if i + 1 < len(args) else ""
                            nxt = i + 2
                        if ch == "c":
                            self.check_code(value, "codice python inline")
                            return RW
                        return self.pymod(value, args[nxt:], ctx)
                    if ch in "WXQ":
                        if j == len(x) - 1:
                            i += 1
                        break
                opts.append(x)
                i += 1
                continue
            break
        if i >= len(args):
            return self.stdin_code("python", ctx, "python")
        script, rest = args[i], args[i + 1:]
        if script.dyn:
            self.deny(f"script python non determinabile ({script.text}): non verificabile")
            return RW
        if all(re.fullmatch(r"-[BIuEsSOq]+", o) for o in opts) and not self.exec_env_set(ctx) \
                and not self.env_tampered and not args[0].dyn and BARE_PYTHON_RE.fullmatch(args[0].text):
            paths = self.resolve_all(script.text, ctx.cwds)
            kit = [p for p in paths if str(p) in self.kit_scripts]
            other = [p for p in paths if str(p) not in self.kit_scripts and p.is_file()]
            if kit and not other:
                if kit[0].name == "tools.py" and rest and rest[0].text == "install":
                    self.installs += 1
                    self.tools_install(rest[1:], ctx)
                return KIT
        self.run_file(script.text, ctx, "python")
        return RW

    def tools_install(self, rest: List[Arg], ctx: Ctx) -> None:
        """`tools.py install` deve nominare un solo strumento, letterale: l'approvazione vale per quello."""
        tools: List[Arg] = []
        bad = ctx.xargs
        i = 0
        while i < len(rest):
            a = rest[i]
            if a.text in TOOLS_INSTALL_VALUE_OPTS:
                i += 2
                continue
            if a.text.split("=", 1)[0] in TOOLS_INSTALL_VALUE_OPTS:
                i += 1
                continue
            if a.text.startswith("-") or a.dyn or a.globby:
                bad = True
            tools.append(a)
            i += 1
        if bad or len(tools) != 1:
            self.deny("tools.py install: nomina esattamente uno strumento, scritto per esteso (niente --all, liste, "
                      "variabili, cicli o xargs): l'approvazione vale per uno strumento", tool=True)

    def pymod(self, mod: str, rest: List[Arg], ctx: Ctx) -> str:
        if mod in ("pip", "pipx", "uv"):
            return self.lang_installer(mod, [Arg(mod)] + rest, ctx)
        if mod == "awscli":
            return self.aws([Arg("aws")] + rest, ctx)
        rel = mod.replace(".", "/")
        for c in ctx.cwds:
            for cand in (c / f"{rel}.py", c / rel / "__main__.py"):
                if c != UNKNOWN_DIR and cand.is_file():
                    self.run_file(str(cand), ctx, "python")
                    return RW
        return RW

    def node(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        if name in ("deno", "bun") and len(t) > 1 and not t[1].startswith("-"):
            sub = t[1]
            if sub == "eval":
                self.check_code(" ".join(t[2:]), f"codice {name} inline", "node")
                return RW
            if sub in ("install", "i", "add", "update", "compile") and (
                    name == "deno" or any(x in ("-g", "--global") for x in t)):
                self.deny_tool(f"{name} {sub}")
                return RW
            if sub == "run":
                pos = [a for a in args[2:] if not a.text.startswith("-")]
                if not pos:
                    return RW
                if pos[0].text.startswith(("http://", "https://", "npm:", "jsr:")):
                    self.deny_tool(f"{name} run di codice remoto")
                    return RW
                if name == "bun" and self.npm_scripts(["bun", "run"] + [a.text for a in pos], ctx, pos[0].text,
                                                      [a.text for a in pos[1:]]):
                    return RW
                self.run_file(pos[0].text, ctx, "node")
                return RW
            if sub in ("test", "task", "fmt", "lint", "check", "build", "upgrade", "init", "repl"):
                return RW
        i = 1
        while i < len(t):
            x = t[i]
            if x in ("-e", "--eval", "-p", "--print", "-pe"):
                self.check_code(t[i + 1] if i + 1 < len(t) else "", f"codice {name} inline", "node")
                return RW
            if x in ("-r", "--require", "--import", "--loader", "--experimental-loader") and i + 1 < len(t):
                if t[i + 1].startswith((".", "/")):
                    self.run_file(t[i + 1], ctx, "node")
                i += 2
                continue
            if x == "-":
                return self.stdin_code(name, ctx, "node")
            if x == "--":
                i += 1
                break
            if x.startswith("-"):
                i += 1
                continue
            break
        if i >= len(args):
            return self.stdin_code(name, ctx, "node")
        if args[i].dyn:
            self.deny(f"script {name} non determinabile ({args[i].text}): non verificabile")
            return RW
        self.run_file(args[i].text, ctx, "node")
        return RW

    def ruby_perl(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        codes: List[str] = []
        inplace = False
        pos: List[Arg] = []
        code_flags = {"ruby": "e", "perl": "eE", "php": "r", "lua": "e"}[name]
        i = 1
        while i < len(args):
            x = args[i].text
            if x == "--":
                pos += args[i + 1:]
                break
            if x.startswith("-") and len(x) > 1 and not x.startswith("--"):
                consumed = False
                for j in range(1, len(x)):
                    ch = x[j]
                    if ch in code_flags:
                        value = x[j + 1:]
                        if not value and i + 1 < len(args):
                            value = args[i + 1].text
                            consumed = True
                        codes.append(value)
                        break
                    if ch == "i" and name == "perl":
                        inplace = True
                        break
                    if ch in "IMmxCdF" and name == "perl":
                        break
                i += 2 if consumed else 1
                continue
            if x.startswith("--"):
                i += 1
                continue
            pos.append(args[i])
            i += 1
        if codes:
            for c in codes:
                self.check_code(c, f"codice {name} inline", name)
            if inplace:
                for a in pos:
                    self.target(a, ctx.cwds)
            return RW
        if pos:
            if pos[0].dyn:
                self.deny(f"script {name} non determinabile ({pos[0].text}): non verificabile")
                return RW
            self.run_file(pos[0].text, ctx, name)
            return RW
        return self.stdin_code(name, ctx, name)

    def awk(self, args: List[Arg], ctx: Ctx) -> str:
        i, prog, progfile, inplace = 1, None, None, False
        while i < len(args):
            x = args[i].text
            if x in ("-F", "-v", "-f", "-i", "-e", "-l", "-E", "--include", "--source", "--file"):
                val = args[i + 1].text if i + 1 < len(args) else ""
                if x in ("-f", "-E", "--file"):
                    progfile = val
                elif x in ("-i", "--include", "-l") and val == "inplace":
                    inplace = True
                elif x in ("-e", "--source"):
                    prog = val
                i += 2
                continue
            if x.startswith(("--include=inplace", "-iinplace")):
                inplace = True
            if x == "--":
                i += 1
                break
            if x.startswith("-") and len(x) > 1:
                i += 1
                continue
            break
        files = args[i:]
        if prog is None and progfile is None and files:
            prog, files = files[0].text, files[1:]
        if progfile:
            for p in self.resolve_all(progfile, ctx.cwds):
                prog = _read_text(p) or prog
        if prog:
            self.check_code(prog, "programma awk", "awk")
        if inplace:
            for a in files:
                self.target(a, ctx.cwds)
        return RW

    # ------------------------------------------------------------ download e installazioni

    def curl(self, args: List[Arg], ctx: Ctx) -> str:
        value_short = set("AbcCdDeEFHKmoPQrTtuUwxXyYz")
        to_file = False
        i = 1
        while i < len(args):
            x = args[i].text
            nxt = args[i + 1].text if i + 1 < len(args) else ""
            if x == "--":
                break
            if x.startswith("--"):
                opt, eq, val = x.partition("=")
                if opt in ("--output", "--output-dir"):
                    v = val if eq else nxt
                    i += 0 if eq else 1
                    to_file = to_file or opt == "--output-dir" or v not in SAFE_OUT
                elif opt in ("--remote-name", "--remote-name-all", "--remote-header-name", "--config"):
                    to_file = True
            elif x.startswith("-") and len(x) > 1:
                for j in range(1, len(x)):
                    ch = x[j]
                    if ch in value_short:
                        v = x[j + 1:]
                        if not v:
                            v = nxt
                            i += 1
                        if (ch == "o" and v not in SAFE_OUT) or ch == "K":
                            to_file = True
                        break
                    if ch == "O":
                        to_file = True
            i += 1
        if ctx.cmd is not None:
            ctx.cmd.download = True
        if to_file or ctx.write_redir:
            self.deny_tool("curl verso un file")
        return RW

    def wget(self, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        safe = any(x in ("--spider", "--version", "-V", "--help", "-h") for x in t)
        for i, x in enumerate(t[1:], 1):
            nxt = t[i + 1] if i + 1 < len(t) else ""
            if x.startswith("--output-document"):
                v = x.split("=", 1)[1] if "=" in x else nxt
                safe = safe or v in SAFE_OUT
            elif x.startswith("-") and not x.startswith("--") and "O" in x:
                v = x[x.index("O") + 1:] or nxt
                safe = safe or v in SAFE_OUT
        if ctx.cmd is not None:
            ctx.cmd.download = True
        if not safe or ctx.write_redir:
            self.deny_tool("wget verso un file")
        return RW

    def pkg_manager(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args[1:]]
        if name in ("pacman", "yay"):
            if not t or t[0].startswith("-Q") or t[0] in VERSION_HELP:
                return RO
            self.deny_tool(f"{name} {t[0]}")
            return RW
        pos = [x for x in t if not x.startswith("-")]
        if not pos or pos[0] in PKG_SAFE or pos[0] in VERSION_HELP:
            if name == "nix-env" and any(x in ("-i", "--install", "-iA", "-u", "--upgrade") for x in t):
                self.deny_tool(f"{name} {' '.join(t[:2])}")
            return RO
        self.deny_tool(f"{name} {pos[0]}")
        return RW

    def system_installer(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        """nix run|shell|profile install, nix-shell -p, dpkg -i, rpm -i|-U|-F, installer -pkg: installano o
        scaricano ed eseguono pacchetti."""
        t = [a.text for a in args[1:]]
        what = None
        if name == "nix":
            pos = [a.text for a in _opt_split(args[1:], {"--extra-experimental-features", "--experimental-features",
                                                         "-I", "--include", "--store", "--log-format"})]
            if pos and (pos[0] in ("run", "shell", "develop") or pos[:2] in (["profile", "install"],
                                                                            ["profile", "add"])):
                what = "nix " + " ".join(pos[:2] if pos[0] == "profile" else pos[:1])
        elif name == "nix-shell":
            if any(x in ("-p", "--packages") or re.fullmatch(r"-[a-zA-Z]*p", x) for x in t):
                what = "nix-shell -p"
        elif name == "dpkg":
            if any(x in ("--install", "--unpack") or re.fullmatch(r"-[a-zA-Z]*i[a-zA-Z]*", x) for x in t):
                what = "dpkg -i"
        elif name == "rpm":
            if any(x in ("--install", "--upgrade", "--freshen", "--reinstall")
                   or (re.fullmatch(r"-[a-zA-Z]+", x) and re.search(r"[iUF]", x) and "q" not in x) for x in t):
                what = "rpm -i/-U"
        elif name == "installer":
            if any(x in ("-pkg", "--pkg") for x in t):
                what = "installer -pkg"
        if what:
            self.deny_tool(what)
        return RW

    def lang_installer(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        pos = [a.text for a in args[1:] if not a.text.startswith("-")]
        first = pos[0] if pos else ""
        second = pos[1] if len(pos) > 1 else ""
        bad = (name == "pip" and first in ("install", "download")) \
            or (name == "pipx" and first in ("install", "run", "inject", "upgrade", "upgrade-all", "reinstall",
                                             "reinstall-all", "install-all")) \
            or (name == "uv" and ((first == "pip" and second in ("install", "sync")) or (
                first == "tool" and second in ("install", "run", "upgrade")))) \
            or (name in ("cargo",) and first in ("install", "binstall")) \
            or (name == "gem" and first in ("install", "update")) \
            or (name == "go" and (first == "install" or (first == "run" and "@" in second)))
        if bad:
            self.deny_tool(f"{name} {first} {second if name in ('uv', 'go') else ''}".strip())
        return RW

    def node_pm(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        value_opts = {"--prefix", "-C", "--dir", "--cwd", "-w", "--workspace", "--filter", "-F", "--location"}
        pos = [a.text for a in _opt_split(args[1:], value_opts)]
        verb = pos[0] if pos else ""
        glob = any(x in ("-g", "--global", "--location=global", "--global=true") for x in t) or \
            any(t[i] == "--location" and i + 1 < len(t) and t[i + 1] == "global" for i in range(len(t)))
        installs = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
                    "add", "update", "up", "upgrade", "udpate", "install-test", "it", "link", "ln"}
        if (glob and verb in installs) or (name == "yarn" and verb == "global" and len(pos) > 1
                                           and pos[1] in ("add", "upgrade", "install")):
            self.deny_tool(f"{name} {verb} globale")
            return RW
        script, extra = None, pos[2:]
        if verb in ("run", "run-script", "rum", "urn"):
            script = pos[1] if len(pos) > 1 else None
        elif verb in ("test", "t", "tst", "start", "stop", "restart"):
            script, extra = {"t": "test", "tst": "test"}.get(verb, verb), pos[1:]
        elif verb in ("install", "i", "ci", "add") or (name == "yarn" and not verb):
            self.npm_scripts(t, ctx, None, [], lifecycle=True)
            return RW
        elif name in ("pnpm", "yarn") and verb:
            script, extra = verb, pos[1:]
        if script:
            self.npm_scripts(t, ctx, script, extra)
        return RW

    def npm_scripts(self, t: List[str], ctx: Ctx, script: Optional[str], extra: List[str],
                    lifecycle: bool = False) -> bool:
        """Legge gli script di package.json (pre/post compresi) e li analizza; False se non trovati."""
        names = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"] \
            if lifecycle else [f"pre{script}", script, f"post{script}"]
        prefix = None
        for i, x in enumerate(t):
            if x in ("--prefix", "-C", "--dir", "--cwd") and i + 1 < len(t):
                prefix = t[i + 1]
            elif x.startswith(("--prefix=", "--dir=", "--cwd=")):
                prefix = x.split("=", 1)[1]
        workspaces = any(x.startswith(("-w", "--workspace", "--filter", "-F", "-r", "--recursive", "-ws"))
                         for x in t)
        files: List[Path] = []
        starts = self.resolve_all(prefix, ctx.cwds) if prefix else [c for c in ctx.cwds if c != UNKNOWN_DIR]
        for start in starts:
            found = self.find_upward(start, ("package.json",))
            if found:
                files.append(found)
                if workspaces:
                    files += [p for p in found.parent.glob("*/*/package.json") if "node_modules" not in p.parts]
                    files += [p for p in found.parent.glob("*/package.json") if "node_modules" not in p.parts]
        hit = False
        for f in files:
            try:
                scripts = json.loads(_read_text(f) or "{}").get("scripts") or {}
            except (ValueError, AttributeError):
                continue
            if not isinstance(scripts, dict):
                continue
            for n in names:
                body = scripts.get(n)
                if isinstance(body, str):
                    hit = True
                    tail = " " + " ".join(shlex.quote(x) for x in extra if x != "--") if n == script else ""
                    self.script(body + tail, [f.parent], ctx.depth + 1)
        return hit

    def find_upward(self, start: Path, names: Tuple[str, ...]) -> Optional[Path]:
        cur = start
        for d in (cur, *cur.parents):
            for n in names:
                if (d / n).is_file():
                    return d / n
            if d == self.proj or not str(d).startswith(str(self.proj)):
                break
        return None

    # ------------------------------------------------------------ make / just / task

    def make(self, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        mfile, mdir, goals, overrides, evals = None, None, [], {}, []
        i = 1
        while i < len(t):
            x = t[i]
            nxt = t[i + 1] if i + 1 < len(t) else None
            if x in ("-E", "--eval") and nxt is not None:
                evals.append(nxt)
                i += 2
                continue
            if x.startswith("--eval="):
                evals.append(x.split("=", 1)[1])
                i += 1
                continue
            if x.startswith("-E") and len(x) > 2:
                evals.append(x[2:])
                i += 1
                continue
            if x in ("-f", "--file", "--makefile") and nxt is not None:
                if args[i + 1].dyn:
                    self.deny(f"`make {x} {nxt}`: Makefile non determinabile (variabile, sostituzione o `<(…)`)")
                    return RW
                mfile, i = nxt, i + 2
                continue
            if x in ("-C", "--directory") and nxt is not None:
                mdir, i = nxt, i + 2
                continue
            if x.startswith(("--file=", "--makefile=", "-f")) and (args[i].dyn or x in ("--file=", "--makefile=")):
                # `--file=$MF`, `--file=<(…)` (la `<(…)` è una parola a sé e il valore resta vuoto)
                self.deny(f"`make {x}`: Makefile non determinabile (variabile, sostituzione o `<(…)`)")
                return RW
            if x.startswith(("--file=", "--makefile=")):
                mfile = x.split("=", 1)[1]
            elif x.startswith("--directory="):
                mdir = x.split("=", 1)[1]
            elif x.startswith("-f") and len(x) > 2:
                mfile = x[2:]
            elif x.startswith("-C") and len(x) > 2:
                mdir = x[2:]
            elif x in ("-I", "-o", "-W", "-l", "--include-dir", "--old-file", "--what-if") and nxt is not None:
                i += 2
                continue
            elif x == "-j" and nxt is not None and nxt.isdigit():
                i += 2
                continue
            elif x.startswith("-"):
                pass
            elif MAKE_SHELL_RE.match(x):
                m = MAKE_SHELL_RE.match(x)
                overrides[m.group(1)] = m.group(2)
            elif ASSIGN_RE.match(x):
                m = ASSIGN_RE.match(x)
                overrides[m.group(1)] = m.group(2)
            else:
                goals.append(x)
            i += 1
        self.check_assigns([(k, v) for k, v in overrides.items() if k != "SHELL"], ctx)
        overrides = {**ctx.env, **overrides}
        for k in ("SHELL", "MAKESHELL", ".SHELLFLAGS"):
            if k in overrides:
                self.make_shell(k, overrides[k], "riga di comando")
        eval_text = "\n".join(evals)
        stdin_text: Optional[str] = None
        if mfile is not None and (mfile == "-" or STDIN_PATH_RE.fullmatch(mfile)):
            # Makefile letto dallo stdin: heredoc/herestring o `< file`; da una pipe o altrove non è verificabile
            bodies = list(ctx.stdin)
            for f in ctx.stdin_files:
                body = None if f.dyn else next(
                    (b for b in (_read_text(p) for p in self.resolve_all(f.text, ctx.cwds)) if b is not None), None)
                if body is not None:
                    bodies.append(body)
            if not bodies:
                self.deny(f"`make -f {mfile}`: Makefile letto dallo stdin, il contenuto non è verificabile")
                return RW
            stdin_text = "\n".join(bodies)
        dirs = self.resolve_all(mdir, ctx.cwds) if mdir else [c for c in ctx.cwds if c != UNKNOWN_DIR]
        if not dirs and (evals or stdin_text is not None):
            self.deny("`make` con Makefile inline in una directory non determinabile: non verificabile")
            return RW
        for d in dirs:
            text: Optional[str] = None
            if stdin_text is not None:
                mf, text = d / "<stdin>", stdin_text
            else:
                if mfile:
                    cands = self.resolve_all(mfile, [d])
                else:
                    cands = [d / n for n in ("GNUmakefile", "makefile", "Makefile")]
                mf = next((c for c in cands if c.is_file()), None)
                if mf is None:
                    if not evals:
                        continue
                    mf, text = d / "<eval>", ""
                elif evals:
                    text = _read_text(mf) or ""
            if evals:
                # `--eval`/`-E` si valutano prima dei Makefile
                text = eval_text + "\n" + (text or "")
            for line in make_lines(mf, text):
                m = None if line.startswith("\t") else MAKE_SHELL_RE.match(line)
                if m:
                    self.make_shell(m.group(1), m.group(2), mf.name)
            recipes = make_recipes(mf, goals, overrides, text=text)
            if recipes:
                self.script(recipes, [mf.parent], ctx.depth + 1)
        return RW

    def make_shell(self, name: str, value: str, origin: str) -> None:
        """`SHELL`/`.SHELLFLAGS` di make: consentite solo le shell standard e le opzioni di `set`."""
        value = value.strip()
        if name == ".SHELLFLAGS":
            toks = value.split()
            ok = all(SAFE_SHELLFLAG_RE.fullmatch(x) for x in toks) and any(re.fullmatch(r"-\w*c\w*", x) for x in toks)
        else:
            ok = bool(SAFE_SHELL_RE.fullmatch(value))
        if not ok:
            self.deny(f"`make`: {name} = {value} ({origin}) fa eseguire le ricette da un programma non verificato")

    def at(self, name: str, args: List[Arg], ctx: Ctx) -> str:
        """`at`/`batch`: lo script del job arriva da `-f file` o dallo stdin, e si analizza come uno script sh."""
        i = 1
        while i < len(args):
            x = args[i].text
            if x[:2] in ("-l", "-r", "-d", "-c"):
                return RO
            if x.startswith("-f"):
                f = Arg(x[2:], args[i].dyn) if len(x) > 2 else (args[i + 1] if i + 1 < len(args) else None)
                paths = [] if f is None or f.dyn else self.resolve_all(f.text, ctx.cwds)
                if not paths or not all(p.is_file() for p in paths):
                    self.deny(f"`{name} -f`: file del job non determinabile o non leggibile, non verificabile")
                    return RW
                self.run_file(f.text, ctx, "sh")
                return RW
            if x in ("-q", "-t") and i + 1 < len(args):
                i += 2
                continue
            i += 1
        self.stdin_code(name, ctx, "sh", required=True)
        return RW

    def just(self, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        jfile, jdir, names = None, None, []
        listing = False
        i = 1
        while i < len(t):
            x = t[i]
            nxt = t[i + 1] if i + 1 < len(t) else None
            if x in ("-f", "--justfile") and nxt is not None:
                jfile, i = nxt, i + 2
                continue
            if x in ("-d", "--working-directory", "--set", "--shell", "--shell-arg", "--dotenv-path",
                     "--dotenv-filename", "--color", "--chooser", "--command-color") and nxt is not None:
                if x == "-d" or x == "--working-directory":
                    jdir = nxt
                i += 2 if x != "--set" else 3
                continue
            if x in ("-l", "--list", "--summary", "--dump", "--version", "--help", "-h", "-V", "--variables",
                     "--show", "-s", "--groups", "--fmt", "--init", "--edit", "-e"):
                listing = True
            elif not x.startswith("-") and not ASSIGN_RE.match(x):
                names.append(x)
            i += 1
        if listing and "--show" not in t and "-s" not in t:
            return RO
        starts = [c for c in ctx.cwds if c != UNKNOWN_DIR]
        for start in starts:
            jf = self.resolve_all(jfile, [start])[0] if jfile else \
                self.find_upward(start, ("justfile", "Justfile", ".justfile", "JUSTFILE"))
            if jf is None or not jf.is_file():
                continue
            text = just_recipes(jf, names)
            if text:
                self.script(text, [Path(jdir).resolve() if jdir else jf.parent], ctx.depth + 1)
        return RW

    def task(self, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        tfile, names, tvars = None, [], {}
        i = 1
        while i < len(t):
            x = t[i]
            nxt = t[i + 1] if i + 1 < len(t) else None
            if x == "--":
                break
            if x in ("-t", "--taskfile", "-d", "--dir", "-o", "--output", "-C", "--concurrency") and nxt is not None:
                if x in ("-t", "--taskfile"):
                    tfile = nxt
                i += 2
                continue
            if x in ("-l", "--list", "-a", "--list-all", "--summary", "--version", "-h", "--help", "--init"):
                return RO
            if not x.startswith("-"):
                m = ASSIGN_RE.match(x)
                if m:
                    tvars[m.group(1)] = m.group(2)
                else:
                    names.append(x)
            i += 1
        for start in [c for c in ctx.cwds if c != UNKNOWN_DIR]:
            tf = self.resolve_all(tfile, [start])[0] if tfile else self.find_upward(
                start, ("Taskfile.yml", "taskfile.yml", "Taskfile.yaml", "taskfile.yaml", "Taskfile.dist.yml",
                        "taskfile.dist.yml", "Taskfile.dist.yaml", "taskfile.dist.yaml"))
            if tf is None or not tf.is_file():
                continue
            text = task_recipes(tf, names, tvars)
            if text:
                self.script(text, [tf.parent], ctx.depth + 1)
        return RW

    # ------------------------------------------------------------ git, find

    def git(self, args: List[Arg], ctx: Ctx) -> str:
        i = 1
        cwds = ctx.cwds
        while i < len(args):
            x = args[i].text
            if x in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path",
                     "--super-prefix"):
                if x == "-c" and i + 1 < len(args):
                    key, _, val = args[i + 1].text.partition("=")
                    self.git_key(key, val, ctx)
                if x == "--config-env" and i + 1 < len(args):
                    self.git_config_env(args[i + 1].text.partition("=")[0])
                if x in ("-C", "--work-tree") and i + 1 < len(args):
                    d = args[i + 1]
                    cwds = [UNKNOWN_DIR] if d.dyn else self.resolve_all(d.text, cwds)
                i += 2
                continue
            if x.startswith("--config-env="):
                self.git_config_env(x.split("=", 2)[1])
            if x.startswith("-"):
                i += 1
                continue
            break
        if i >= len(args):
            return RO
        sub = args[i]
        if sub.dyn:
            self.deny("`git`: sottocomando non determinabile")
            return RW
        if sub.text in ("apply", "am"):
            self.deny("git apply/patch scrivono file senza passare dai controlli: applica le modifiche con Write/Edit")
            return RW
        if sub.text == "config":
            self.git_config(args[i + 1:], ctx)
        rest = args[i + 1:]
        if sub.text == "filter-branch":
            self.deny("`git filter-branch` riscrive la storia eseguendo filtri shell: non verificabile, lo usa "
                      "solo l'utente")
            return RW
        self.git_runs(sub.text, rest, ctx)
        self.output_opts(rest, cwds, short_o=sub.text in ("archive", "format-patch"),
                         names=("--output", "--output-directory"))
        self.git_tree(sub.text, rest, cwds)
        return RO if sub.text in READONLY_GIT else RW

    def git_runs(self, sub: str, rest: List[Arg], ctx: Ctx) -> None:
        """Sottocomandi git che lanciano comandi: `bisect run`, `submodule foreach`, `difftool/mergetool -x`."""
        t = [a.text for a in rest]
        if sub == "bisect" and t[:1] == ["run"] and len(rest) > 1:
            self.run(rest[1:], ctx.nested())
        elif sub == "submodule" and "foreach" in t:
            k = t.index("foreach") + 1
            while k < len(t) and t[k].startswith("-"):
                k += 1
                if t[k - 1] == "--":
                    break
            if k < len(t):
                self.script(" ".join(t[k:]), ctx.cwds, ctx.depth + 1)
        elif sub in ("difftool", "mergetool"):
            label = f"git {sub} --extcmd"
            j = 0
            while j < len(t):
                x = t[j]
                if x == "--":
                    break
                lo = long_opt(x, ("extcmd",))
                if lo:
                    if lo[1] is not None:
                        self.program_value(Arg(lo[1], rest[j].dyn), label, ctx)
                    else:
                        self.program_value(rest[j + 1] if j + 1 < len(t) else None, label, ctx)
                        j += 1
                elif x.startswith("-") and not x.startswith("--"):
                    for pos, ch in enumerate(x[1:], 1):
                        if ch in "xt":
                            if x[pos + 1:]:
                                value: Optional[Arg] = Arg(x[pos + 1:], rest[j].dyn)
                            else:
                                value = rest[j + 1] if j + 1 < len(t) else None
                                j += 1
                            if ch == "x":
                                self.program_value(value, label, ctx)
                            break
                j += 1

    def git_tree(self, sub: str, rest: List[Arg], cwds: List[Path]) -> None:
        """git che riscrive il working tree: consentito solo se ogni pathspec è fuori da infra_root e dai file
        protetti; senza pathspec (cambio di branch, merge, stash apply…) tocca tutto l'albero e si rifiuta."""
        t = [a.text for a in rest]

        def short(ch: str) -> bool:
            return any(x.startswith("-") and not x.startswith("--") and ch in x[1:] for x in t)

        def split(value_opts: Set[str]) -> Tuple[List[Arg], Optional[List[Arg]]]:
            if "--" in t:
                k = t.index("--")
                return _opt_split(rest[:k], value_opts), rest[k + 1:]
            return _opt_split(rest, value_opts), None

        whole = False
        paths: List[Arg] = []
        if sub == "checkout":
            before, after = split({"-b", "-B", "--orphan", "--conflict", "--pathspec-from-file"})
            creates = any(x in ("-b", "-B", "--orphan") for x in t)
            if after is not None:
                paths, whole = after, not after
            elif not before:
                whole = any(x.startswith("--pathspec-from-file") or x == "--force" for x in t) or short("f")
            elif creates:
                whole = True
            elif len(before) == 1:
                if not before[0].dyn and any(p.exists() for p in self.resolve_all(before[0].text, cwds)):
                    paths = before
                else:
                    whole = True
            else:
                paths = before[1:]
        elif sub == "switch":
            before, _ = split({"-c", "-C", "--create", "--force-create", "--orphan", "--conflict"})
            whole = bool(before)
        elif sub == "restore":
            if (("--staged" in t or short("S")) and not ("--worktree" in t or short("W"))):
                return
            before, after = split({"-s", "--source", "--conflict", "--pathspec-from-file"})
            paths = after if after is not None else before
            whole = any(x.startswith("--pathspec-from-file") for x in t)
        elif sub == "stash":
            pos = _opt_split(rest, {"-m", "--message"})
            whole = bool(pos) and pos[0].text in ("apply", "pop", "branch")
        elif sub == "reset":
            whole = any(x in ("--hard", "--merge", "--keep") for x in t)
        elif sub in GIT_TREE_WRITERS:
            whole = True
        elif sub == "bisect":
            pos = _opt_split(rest, {"--term-new", "--term-bad", "--term-old", "--term-good"})
            whole = len(pos) > 1 and pos[0].text == "start" and "--no-checkout" not in t
        elif sub == "sparse-checkout":
            pos = _opt_split(rest, set())
            whole = bool(pos) and pos[0].text in ("set", "add", "reapply", "disable")
        elif sub == "submodule":
            pos = _opt_split(rest, set())
            whole = bool(pos) and pos[0].text == "update"
        elif sub == "worktree":
            pos = _opt_split(rest, set())
            whole = bool(pos) and pos[0].text in ("add", "move")
        elif sub == "checkout-index":
            whole = any(x in ("-a", "--all", "--stdin") for x in t)
            paths = _opt_split(rest, {"--prefix", "--stage"})
        elif sub == "update-index":
            whole = any(x in ("--index-info", "--stdin") for x in t)
            paths = [Arg(a.text.rsplit(",", 1)[-1], a.dyn, a.globby) for a in _opt_split(rest, set())]
        elif sub == "mv":
            self.writers("mv", [Arg("mv")] + rest, Ctx(cwds, 0))
            return
        else:
            return
        if whole and UNKNOWN_DIR not in cwds and all(rules.rel_to_project(str(c), self.proj) is None
                                                     for c in cwds):
            whole = False  # repository fuori dal progetto (git -C altrove)
        if not whole:
            whole = any(self.git_path_guarded(a, cwds) for a in paths)
        if whole:
            self.deny(f"`git {sub}` riscrive file del working tree (IaC sotto infra_root o file protetti) senza "
                      "passare dai controlli: modifica i file con Write/Edit, o lascia l'operazione all'utente")

    def git_path_guarded(self, a: Arg, cwds: List[Path]) -> bool:
        """Pathspec che può toccare IaC sotto infra_root, .env o file protetti (o non determinabile)."""
        if a.dyn or a.globby or re.search(r"[*?\[]", a.text) or a.text.startswith(":"):
            return True
        if UNKNOWN_DIR in cwds and not os.path.isabs(os.path.expanduser(a.text)):
            return True
        for p in self.resolve_all(a.text, cwds):
            rel = rules.rel_to_project(str(p), self.proj)
            if rel is None:
                continue
            rel = "" if rel == "." else rel
            low = rel.lower()
            base = low.rsplit("/", 1)[-1]
            # cartella (esistente, con / finale o senza estensione se assente): può contenere IaC
            folder = p.is_dir() or a.text.endswith("/") or (not p.exists() and "." not in base)
            irel = rules.infra_rel(rel, self.cfg)
            if rel == "" or (folder and self.in_infra_scope(rel)) or (irel is not None and rules.is_iac_file(irel)) \
                    or rules.protected_reason(rel, self.cfg) or is_env_name(base) or low == ".git" \
                    or low.startswith(".git/") or any(pre.startswith(low + "/") for pre, _ in rules.PROTECTED_PATHS):
                return True
        return False

    def git_config(self, args: List[Arg], ctx: Ctx) -> None:
        t = [a.text for a in args]
        if any(x in ("--get", "--get-all", "--get-regexp", "--list", "-l", "--unset", "--unset-all",
                     "--remove-section", "--rename-section", "--show-origin", "--name-only") for x in t):
            return
        if any(x in ("--edit", "-e") for x in t):
            return
        pos = [a for a in _opt_split(args, {"-f", "--file", "--blob", "--type", "--default", "--comment"})]
        if pos and pos[0].text in ("get", "list", "unset", "rename-section", "remove-section", "edit"):
            return
        if pos and pos[0].text == "set":
            pos = pos[1:]
        if len(pos) >= 2:
            self.git_key(pos[0].text, pos[1].text, ctx)

    def git_config_env(self, key: str) -> None:
        """`git --config-env=<chiave>=<VARIABILE>`: il valore arriva da una variabile e non si può verificare."""
        k = key.lower()
        if k.startswith("alias.") or k in GIT_EXEC_KEYS or GIT_EXEC_KEY_RE.fullmatch(k):
            self.deny(f"configurazione git che esegue comandi ({key}) presa da una variabile: non verificabile")

    def git_key(self, key: str, val: str, ctx: Ctx) -> None:
        k = key.lower()
        if k.startswith("alias."):
            if val.startswith("!"):
                self.script(val[1:], ctx.cwds, ctx.depth + 1)
            elif val.split()[:1] and val.split()[0] in ("apply", "am"):
                self.deny("git apply/patch scrivono file senza passare dai controlli: applica le modifiche con "
                          "Write/Edit")
            return
        if k in GIT_EXEC_KEYS or GIT_EXEC_KEY_RE.fullmatch(k):
            self.deny(f"configurazione git che esegue comandi ({key}): la imposta solo l'utente")

    def find(self, args: List[Arg], ctx: Ctx) -> str:
        t = [a.text for a in args]
        names = [args[i + 1] for i, x in enumerate(t[:-1]) if x in ("-name", "-iname", "-path", "-ipath",
                                                                         "-wholename", "-iwholename")]
        kind = RO
        if any(x in ("-delete", "-fprint", "-fprint0", "-fprintf", "-fls") for x in t):
            kind = RW
        i = 0
        while i < len(t):
            if t[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                kind = RW
                j = i + 1
                while j < len(t) and t[j] not in (";", "+"):
                    j += 1
                sub = args[i + 1:j]
                fills = [Arg(n.text, n.dyn, True) for n in names] or [Arg("{}", dyn=True)]
                for fill in fills:
                    self.run([fill if a.text == "{}" else a for a in sub], ctx.nested())
                i = j
            i += 1
        return kind

    # ------------------------------------------------------------ scritture

    def writers(self, name: str, args: List[Arg], ctx: Ctx) -> None:
        rest = args[1:]
        t = [a.text for a in rest]
        cw = ctx.cwds

        def positional(value_opts: Set[str] = frozenset()) -> List[Arg]:
            return _opt_split(rest, value_opts)

        if name in ("tee", "sponge", "truncate", "touch", "ed", "ex", "vi", "vim", "nvim"):
            for a in positional({"-s", "--size", "-r", "--reference", "-d", "-t", "-c", "-S"}):
                self.target(a, cw)
        elif name in ("sed", "gsed"):
            inplace = any(x.startswith(("-i", "--in-place")) or x == "-I" or
                          (x.startswith("-") and not x.startswith("--") and "i" in x[1:]) for x in t)
            scripts = [t[i + 1] for i, x in enumerate(t[:-1]) if x in ("-e", "--expression")]
            scripts += [x.split("=", 1)[1] for x in t if x.startswith("--expression=")]
            skip = {i + 1 for i, x in enumerate(t[:-1]) if x in ("-i", "-I") and re.fullmatch(r"(?:\.[\w.-]*)?",
                                                                                              t[i + 1])}
            files = [a for i, a in enumerate(rest) if i not in skip and a in
                     positional({"-e", "--expression", "-f", "--file", "-l", "--line-length"})]
            if not scripts and not any(x in ("-f", "--file") or x.startswith("--file=") for x in t) and files:
                scripts.append(files.pop(0).text)
            for s in scripts:
                for m in re.finditer(r"(?:^|[;\n}/])\s*[0-9$,]*\s*[wW]\s+(\S+)", s):
                    self.target(Arg(m.group(1)), cw)
                if CLOUD_WORD_RE.search(s) and re.search(r"(?:^|[;\n])\s*[0-9$,]*\s*e\b|/[gpiImMw0-9]*e[gpiImM0-9]*"
                                                         r"(?:\s|;|$)", s):
                    self.deny("`sed` con il comando `e` lancia comandi: non verificabile")
            if inplace:
                for a in files:
                    if a.text:
                        self.target(a, cw)
        elif name in ("perl",):
            self.ruby_perl("perl", args, ctx)
        elif name in ("awk", "gawk", "mawk", "nawk"):
            self.awk(args, ctx)
        elif name == "yq":
            if any(x in ("-i", "--inplace") or x.startswith("--inplace") for x in t):
                for a in positional({"-o", "--output-format", "-p", "--input-format", "--from-file"}):
                    self.target(a, cw)
        elif name in ("cp", "mv", "install", "ln", "rsync", "scp", "ditto"):
            if name == "install" and any(x in ("-d", "--directory") for x in t):
                return
            if name == "ln" or (name == "cp" and any(
                    x in ("--link", "--symbolic-link") or (x.startswith("-") and not x.startswith("--")
                                                            and re.search(r"[sl]", x[1:])) for x in t)):
                self.links(name, rest, ctx)
            if name == "ditto" and any(x.startswith("-") and not x.startswith("--") and "x" in x[1:] for x in t):
                pos = positional()
                if pos:
                    self.target(pos[-1], cw, extract=True)
                return
            tdir = None
            for i, x in enumerate(t):
                if x in ("-t", "--target-directory") and i + 1 < len(t):
                    tdir = rest[i + 1]
                elif x.startswith("--target-directory="):
                    tdir = Arg(x.split("=", 1)[1])
            value_opts = {"-t", "--target-directory", "-S", "--suffix", "-m", "--mode", "-o", "--owner", "-g",
                          "--group", "-e", "--rsh", "--exclude", "--include", "-f", "--filter", "-P", "-i", "-F",
                          "-l", "-c"} if name in ("rsync", "scp", "install") else {"-t", "--target-directory", "-S",
                                                                                   "--suffix"}
            pos = positional(value_opts)
            if tdir is not None:
                dest, sources = tdir, pos
            elif len(pos) >= 2:
                dest, sources = pos[-1], pos[:-1]
            else:
                return
            sources = [Arg(s.text, True, s.globby) if ":" in s.text and name in ("rsync", "scp") else s
                       for s in sources]
            dir_hint = tdir is not None or any(s.dyn or self.any_dir(s, cw) for s in sources)
            if name == "ditto" and tdir is None:
                # ditto copia il contenuto della sorgente nella destinazione: il nome di destinazione è il file
                self.target(dest, cw)
            self.target(dest, cw, sources=sources, dir_hint=dir_hint)
        elif name == "dd":
            for x in t:
                if x.startswith("of="):
                    self.target(Arg(x[3:]), cw)
        elif name == "sort":
            for i, x in enumerate(t):
                lo = long_opt(x, ("compress-program",))
                if lo:
                    self.program_value(Arg(lo[1], rest[i].dyn) if lo[1] is not None
                                       else (rest[i + 1] if i + 1 < len(t) else None), "sort --compress-program", ctx)
                if x in ("-o", "--output") and i + 1 < len(t):
                    self.target(rest[i + 1], cw)
                elif x.startswith("--output="):
                    self.target(Arg(x.split("=", 1)[1]), cw)
        elif name in ("tar", "bsdtar", "gtar"):
            self.tar_programs(name, rest, ctx)
            extract = any(x in ("--extract", "--get") for x in t) or any(
                x.startswith("-") and not x.startswith("--") and "x" in x for x in t) or (
                t and not t[0].startswith("-") and "x" in t[0])
            if extract:
                dest = "."
                for i, x in enumerate(t):
                    if x in ("-C", "--directory") and i + 1 < len(t):
                        dest = t[i + 1]
                    elif x.startswith("--directory="):
                        dest = x.split("=", 1)[1]
                self.target(Arg(dest), cw, extract=True)
        elif name == "unzip":
            if any(x in ("-l", "-t", "-p", "-Z", "-v") for x in t):
                return
            dest = next((t[i + 1] for i, x in enumerate(t[:-1]) if x == "-d"), ".")
            self.target(Arg(dest), cw, extract=True)
        elif name in ("7z", "7za", "7zz"):
            if t and t[0] in ("x", "e"):
                dest = next((x[2:] for x in t if x.startswith("-o")), ".")
                self.target(Arg(dest), cw, extract=True)
        elif name == "cpio":
            if any(x.startswith("-i") or x == "--extract" for x in t):
                self.target(Arg("."), cw, extract=True)
            elif any(x == "--pass-through" or (x.startswith("-") and not x.startswith("--") and "p" in x[1:])
                     for x in t):
                pos = positional({"-H", "-F", "-E", "-R", "-I", "-O", "-M", "-C", "--format", "--file"})
                self.target(pos[-1] if pos else Arg("."), cw, extract=True)

    def links(self, name: str, rest: List[Arg], ctx: Ctx) -> None:
        """`ln`, `link`, `cp -s/-l`: un link (simbolico o fisso) sotto infra_root fa leggere a Terraform un file che
        i controlli non vedono (o che cambia fuori da Write/Edit): rifiutato. Si controlla il percorso del link, non
        quello a cui punta."""
        t = [a.text for a in rest]
        tdir: Optional[Arg] = None
        for i, x in enumerate(t):
            if x in ("-t", "--target-directory") and i + 1 < len(t):
                tdir = rest[i + 1]
            elif x.startswith("--target-directory="):
                tdir = Arg(x.split("=", 1)[1])
        no_deref = any(x in ("-T", "--no-target-directory", "-n", "--no-dereference") for x in t)
        pos = _opt_split(rest, {"-t", "--target-directory", "-S", "--suffix"}) if name != "link" else rest
        if tdir is not None:
            dests = [(tdir, True, pos)]
        elif len(pos) == 1:
            dests = [(Arg("."), True, pos)]
        elif len(pos) >= 2:
            dests = [(pos[-1], None, pos[:-1])]
        else:
            return
        for dest, is_dir, sources in dests:
            if dest.dyn:
                self.deny(f"`{name}`: link creato in un percorso non determinabile ({dest.text}): non verificabile")
                return
            for c in self.candidates(dest, ctx.cwds):
                for d in self.resolve_dest(c, ctx.cwds):
                    into = is_dir if is_dir is not None else (d.is_dir() and not (no_deref and d.is_symlink()))
                    paths = [d / (s.text.rstrip("/").rsplit("/", 1)[-1] or "x") for s in sources] if into else [d]
                    for lp in paths:
                        rel = rules.rel_to_project(str(lp.parent), self.proj)
                        if rel is None:
                            continue
                        rel = lp.name if rel in ("", ".") else f"{rel}/{lp.name}"
                        if self.in_infra_scope(rel) or (self.protect and rules.protected_reason(rel, self.cfg)):
                            self.deny(f"`{name}` crea un link in {rel}: Terraform seguirebbe il link e i controlli "
                                      "di kynfra non vedrebbero il contenuto; sotto infra_root niente link, usa i "
                                      "file veri (Write/Edit)")
                            return

    def resolve_dest(self, text: str, cwds: List[Path]) -> List[Path]:
        """Come resolve_all ma senza seguire l'ultimo componente (che può essere già un link)."""
        t = os.path.expanduser(text).rstrip("/") or "/"
        bases = [Path(t)] if os.path.isabs(t) else [c / t for c in cwds if c != UNKNOWN_DIR]
        out = []
        for b in bases:
            if b.name in ("", ".", ".."):
                out.append(b.resolve())
            else:
                out.append(b.parent.resolve() / b.name)
        return out

    def producers(self, name: str, args: List[Arg], ctx: Ctx) -> None:
        """Comandi che producono file (decompressori, base64, xxd, openssl, pax, split): i percorsi di output
        passano dai controlli delle scritture."""
        rest = args[1:]
        t = [a.text for a in rest]
        cw = ctx.cwds

        def short(ch: str) -> bool:
            return any(x.startswith("-") and not x.startswith("--") and ch in x[1:] for x in t)

        if name in DECOMPRESSORS:
            decomp = name.startswith("un") or name.startswith("gun") or name.startswith("bun") \
                or any(x in ("--decompress", "--uncompress") for x in t) or short("d")
            if not decomp:
                return
            self.output_opts(rest, cw, short_o=name in ("zstd", "unzstd"), names=("--output",))
            if any(x in ("--stdout", "--to-stdout", "--list", "--test") for x in t) or short("c") or short("l") \
                    or short("t"):
                return
            suffix = None
            for i, x in enumerate(t):
                if x in ("-S", "--suffix") and i + 1 < len(t):
                    suffix = t[i + 1]
                elif x.startswith("--suffix="):
                    suffix = x.split("=", 1)[1]
            restore_name = "--name" in t or short("N")
            for a in _opt_split(rest, {"-o", "-S", "--suffix", "-T", "--threads"}):
                if restore_name:
                    # -N: il nome di output viene dall'intestazione dell'archivio, non dalla riga di comando
                    self.unknown_names(Arg(os.path.dirname(a.text) or ".", a.dyn, a.globby), cw, name + " -N")
                    continue
                low = a.text.lower()
                if suffix:
                    ext = suffix.lower() if low.endswith(suffix.lower()) else ""
                    out = a.text[:-len(ext)] if ext else a.text
                else:
                    ext = next((e for e in DECOMP_SUFFIXES if low.endswith(e)), "")
                    out = a.text[:-len(ext)] + DECOMP_SUFFIXES[ext] if ext else a.text
                # senza suffisso noto il decompressore cerca <nome><suffisso> e scrive <nome>
                self.target(Arg(out, a.dyn, a.globby), cw)
        elif name == "base64":
            self.output_opts(rest, cw, short_o=True)
        elif name == "xxd":
            pos = _opt_split(rest, {"-c", "-cols", "-g", "-groupsize", "-l", "-len", "-s", "-seek", "-o", "-n",
                                    "-name"})
            if len(pos) >= 2:
                self.target(pos[1], cw)
        elif name == "openssl":
            for i, x in enumerate(t[:-1]):
                if x in ("-out", "-keyout"):
                    self.target(rest[i + 1], cw)
        elif name == "pax":
            if short("r"):
                pos = _opt_split(rest, {"-f", "-s", "-o", "-x", "-b", "-p", "-B", "-G", "-T", "-U"})
                dest = pos[-1] if short("w") and pos else Arg(".")
                self.target(dest, cw, extract=True)
        elif name == "split":
            pos = _opt_split(rest, {"-b", "--bytes", "-l", "--lines", "-n", "--number", "-a", "--suffix-length",
                                    "-C", "--line-bytes", "-t", "--separator", "--additional-suffix", "--filter"})
            suffix = ""
            for i, x in enumerate(t):
                if x == "--additional-suffix" and i + 1 < len(t):
                    suffix = t[i + 1]
                elif x.startswith("--additional-suffix="):
                    suffix = x.split("=", 1)[1]
            prefix = pos[1] if len(pos) > 1 else Arg("x")
            self.target(Arg(prefix.text + "aa" + suffix, prefix.dyn, prefix.globby), cw)
            self.unknown_names(Arg(os.path.dirname(prefix.text) or ".", prefix.dyn, prefix.globby), cw, name)
        elif name == "csplit":
            prefix = Arg("xx")
            for i, x in enumerate(t):
                if x in ("-f", "--prefix") and i + 1 < len(t):
                    prefix = rest[i + 1]
                elif x.startswith("--prefix="):
                    prefix = Arg(x.split("=", 1)[1], rest[i].dyn)
                elif x.startswith("-f") and len(x) > 2:
                    prefix = Arg(x[2:], rest[i].dyn)
            self.target(Arg(prefix.text + "00", prefix.dyn, prefix.globby), cw)
            self.unknown_names(Arg(os.path.dirname(prefix.text) or ".", prefix.dyn, prefix.globby), cw, name)

    def unknown_names(self, d: Arg, cwds: List[Path], label: str) -> None:
        """Comandi che creano in `d` file con nomi non determinabili dalla riga di comando (gunzip -N,
        split/csplit con suffissi generati): si rifiutano se `d` è sotto infra_root, dove possono nascere file IaC."""
        if d.dyn:
            self.deny(f"`{label}` scrive in una cartella non determinabile ({d.text}): usa Write/Edit")
            return
        for t in self.candidates(d, cwds):
            if UNKNOWN_DIR in cwds and not os.path.isabs(os.path.expanduser(t)):
                self.deny(f"`{label}` scrive in una cartella non determinabile: usa Write/Edit")
                return
            for p in self.resolve_all(t, cwds):
                rel = rules.rel_to_project(str(p), self.proj)
                if rel is None:
                    continue
                rel = "" if rel == "." else rel
                if self.in_infra_scope(rel):
                    self.deny(f"`{label}` crea in {rel or '.'} file con nomi generati che possono essere IaC: usa "
                              "una cartella fuori da infra_root, o Write/Edit")
                    return

    def any_dir(self, a: Arg, cwds: List[Path]) -> bool:
        for t in self.candidates(a, cwds):
            for p in self.resolve_all(t, cwds):
                if p.is_dir():
                    return True
        return False

    def target(self, a: Arg, cwds: List[Path], sources: Optional[List[Arg]] = None, dir_hint: bool = False,
               extract: bool = False) -> None:
        """Controlla un percorso in cui il comando scrive."""
        if a.dyn and not a.globby:
            if not SAFE_DYN_TARGET.match(a.text):
                self.deny(f"scrittura via shell su un percorso non determinabile ({a.text}): usa Write/Edit")
            return
        if a.dyn:
            self.deny(f"scrittura via shell su un percorso non determinabile ({a.text}): usa Write/Edit")
            return
        for t in self.candidates(a, cwds):
            if t in SAFE_REDIRECT or not t:
                continue
            if UNKNOWN_DIR in cwds and not os.path.isabs(os.path.expanduser(t)):
                base = t.rstrip("/").rsplit("/", 1)[-1]
                if is_env_name(base) or t.lower().endswith(rules.IAC_EXT) or PROTECTED_RE.search(t):
                    self.deny(f"scrittura via shell di {t} in una cartella non determinabile: usa Write/Edit")
            for p in self.resolve_all(t, cwds):
                self.writes.add(str(p))
                rel = rules.rel_to_project(str(p), self.proj)
                if rel is None:
                    continue
                is_dir = extract or (sources is not None and (dir_hint or t.endswith("/") or p.is_dir()))
                self.check_rel(rel, is_dir, sources, cwds)

    def check_rel(self, rel: str, is_dir: bool, sources: Optional[List[Arg]], cwds: List[Path]) -> None:
        low = rel.lower()
        shown = rel or "."
        if self.protect and rules.protected_reason(rel, self.cfg):
            self.deny(f"scrittura via shell su un file protetto ({shown})")
            return
        if low == ".git/config" or low.startswith(".git/hooks/") or low == ".git/hooks" \
                or rules.GIT_MODULE_RE.fullmatch(low):
            self.deny(f"scrittura via shell di {shown}: gli hook e la configurazione di git possono eseguire comandi")
            return
        if is_env_name(low.rsplit("/", 1)[-1]):
            self.deny(f"scrittura via shell di {shown}: i file .env si scrivono con Write/Edit, così le regole "
                      "valutano il contenuto")
            return
        irel = rules.infra_rel(rel, self.cfg)
        if irel is not None and not is_dir and rules.is_iac_file(irel):
            self.deny(f"scrittura via shell di {shown}: i file IaC si scrivono con Write/Edit, così le regole di "
                      "kynfra valutano il contenuto")
            return
        if not is_dir or not self.in_infra_scope(rel):
            return
        if sources is None:
            self.deny(f"estrazione di archivi in {shown}: può creare file IaC senza passare dalle regole")
            return
        for s in sources:
            if s.dyn:
                self.deny(f"copia via shell in {shown} da una sorgente non determinabile: usa Write/Edit")
                return
            for t in self.candidates(s, cwds):
                base = t.rstrip("/").rsplit("/", 1)[-1]
                sub = (irel + "/" if irel else "") + base if irel is not None else base
                if is_env_name(base) or base.lower().endswith(rules.IAC_EXT) or rules.is_iac_file(sub) \
                        or re.search(r"[*?\[]", t) or self.dir_has_iac(t, cwds):
                    self.deny(f"copia via shell di {t} in {shown}: i file IaC si scrivono con Write/Edit, così le "
                              "regole di kynfra valutano il contenuto")
                    return

    def in_infra_scope(self, rel: str) -> bool:
        root = self.cfg.get("infra_root", ".")
        if root in ("", "."):
            return True
        return rel in ("", root) or rel.startswith(root + "/") or root.startswith(rel + "/")

    def dir_has_iac(self, t: str, cwds: List[Path]) -> bool:
        for p in self.resolve_all(t, cwds):
            if not p.is_dir():
                continue
            seen = 0
            for _dirpath, _dirs, files in os.walk(p):
                for f in files:
                    seen += 1
                    if f.lower().endswith(rules.IAC_EXT) or is_env_name(f) or seen > 5000:
                        return True
        return False


# ---------------------------------------------------------------- interfaccia

def command_text(event: dict) -> str:
    ti = event.get("tool_input") or {}
    if isinstance(ti, str):
        return ti
    cmd = ti.get("command") if isinstance(ti, dict) else None
    if isinstance(cmd, list):
        cmd = " ".join(shlex.quote(str(c)) for c in cmd)
    return cmd if isinstance(cmd, str) else ""


def analyze(cmd: str, cwd: Path, proj: Path, cfg: dict) -> Analyzer:
    an = Analyzer(proj, cfg, cwd)
    try:
        an.script(cmd, [cwd], 0)
        an.finish()
    except RecursionError:
        an.deny("comando annidato troppo in profondità: non verificabile")
    except Exception as e:  # una guardia che si rompe non deve lasciar passare il comando
        an.deny(f"analisi del comando non riuscita ({type(e).__name__}): non verificabile")
    return an


def check(cmd: str, cwd: Path, proj: Path, cfg: dict) -> List[str]:
    """Motivi di rifiuto del comando (vuoto = consentito)."""
    return analyze(cmd, cwd, proj, cfg).reasons


CLAUDE_TOOLS = {"Bash"}  # nome del tool shell in Claude Code; Codex usa shell, exec_command, local_shell


def _output(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}, ensure_ascii=False))


def _evaluate(event: dict, cmd: str) -> Tuple[List[str], bool, List[str]]:
    """(motivi di rifiuto, serve /kynfra:kynfra-tools, comandi tools.py install da far approvare all'utente)."""
    cwd = Path(event.get("cwd") or os.getcwd()).resolve()
    projects = [rules.find_project_dir(str(cwd))]
    if rules.load_config(projects[0]) is None:
        projects = rules.discover_projects(cwd)
    reasons: List[str] = []
    installs: List[str] = []
    tool = False
    for proj in projects:
        cfg = rules.load_config(proj)
        if cfg is None:
            continue
        hc.record_baseline(event, proj)
        an = analyze(cmd, cwd, proj, cfg)
        tool = tool or an.tool
        for r in an.reasons:
            if r not in reasons:
                reasons.append(r)
        if an.installs:
            installs.append(cmd)
    return reasons, tool, installs


def main() -> int:
    event = hc.read_event()
    hc.debug_dump(event, "bash")
    cmd = command_text(event)
    if not cmd.strip():
        return 0
    try:
        reasons, tool, installs = _evaluate(event, cmd)
    except Exception as e:  # fail closed dentro un progetto kynfra (config illeggibile, errore imprevisto)
        if hc.in_kynfra_project(event):
            _output("deny", f"Comando rifiutato: errore interno della guardia di kynfra ({type(e).__name__}), comando "
                            "non verificabile. Segnala il problema; controlla che .kynfra/config.json sia valido.")
        return 0
    if reasons:
        reason = ("Comando rifiutato dalle regole di infrastruttura del progetto (kynfra):\n"
                  + "\n".join(f"- {r}" for r in reasons)
                  + "\nNon aggirare i controlli: segui la skill kynfra-architecture (il codice IaC si scrive con "
                    "Write/Edit; apply, plan e le CLI cloud mutanti li esegue il DevOps).")
        if tool:
            reason += "\nPer gli strumenti esterni usa /kynfra:kynfra-tools (un'installazione approvata per strumento)."
        _output("deny", reason)
        return 0
    if installs:
        # spec 7.3.1: ogni installazione la autorizza l'utente, non basta che il comando sia ben formato
        if event.get("tool_name") in CLAUDE_TOOLS:
            _output("ask", "kynfra: installazione di uno strumento esterno con tools.py. Approva solo se hai letto "
                           f"e accettato il piano (`tools.py plan`) per questo strumento:\n  {cmd}")
        else:  # Codex non supporta "ask" nei PreToolUse: l'installazione la lancia l'utente
            _output("deny", "L'installazione di strumenti esterni la autorizza l'utente ogni volta e Codex non può "
                            "chiedergliela da un hook: mostra all'utente il piano (`tools.py plan <tool>`) e chiedigli "
                            f"di eseguire lui stesso, nel terminale:\n  {cmd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
