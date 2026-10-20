#!/usr/bin/env bash
# Installer di kynfra: regole, agenti e controlli automatici per Terraform su AWS, per Claude Code e Codex.
#
# Uso:
#   ./install.sh [--target DIR] [--iac terraform|opentofu] [--providers aws] [--infra-root DIR] [--project NAME]
#                [--envs dev,staging,prod] [--region eu-south-1] [--account-id ID] [--agents claude|codex|both]
#                [--ci github|none] [--scope local|project|user] [--no-plugin] [--force] [--uninstall]
#
# Rilanciarlo è sicuro: aggiorna il kit, rigenera i blocchi in CLAUDE.md e AGENTS.md e non sovrascrive
# configurazione, regole o .tflint.hcl esistenti (salvo --force). Non scrive file IaC, non lancia terraform
# e non scarica strumenti (si fa con tools.py, uno alla volta).
set -euo pipefail

KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # cartella del plugin
TARGET="."
IAC=""
PROVIDERS="aws"
INFRA_ROOT=""
PROJECT=""
ENVS="dev,staging,prod"
REGION="eu-south-1"
ACCOUNT_ID=""
AGENTS="both"
CI="github"
SCOPE="local"
NO_PLUGIN=0
FORCE=0
UNINSTALL=0
KIT_REL="tools/kynfra"

die()  { printf '\033[31mErrore:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m•\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }

usage() { awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --target)     TARGET="${2:?manca la cartella}"; shift 2 ;;
    --iac)        IAC="${2:?}"; shift 2 ;;
    --providers)  PROVIDERS="${2:?}"; shift 2 ;;
    --infra-root) INFRA_ROOT="${2:?}"; shift 2 ;;
    --project)    PROJECT="${2:?}"; shift 2 ;;
    --envs)       ENVS="${2:?}"; shift 2 ;;
    --region)     REGION="${2:?}"; shift 2 ;;
    --account-id) ACCOUNT_ID="${2:?}"; shift 2 ;;
    --agents)     AGENTS="${2:?}"; shift 2 ;;
    --ci)         CI="${2:?}"; shift 2 ;;
    --scope)      SCOPE="${2:?}"; shift 2 ;;
    --no-plugin)  NO_PLUGIN=1; shift ;;
    --force)      FORCE=1; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    -h|--help)    usage ;;
    *) die "opzione sconosciuta: $1" ;;
  esac
done

command -v python3 >/dev/null || die "serve python3 (solo libreria standard)"
mkdir -p "$TARGET"
TARGET="$(cd "$TARGET" && pwd)"
[ -n "$TARGET" ] && [ "$TARGET" != "/" ] || die "cartella di destinazione non valida"
case "$AGENTS" in claude|codex|both) ;; *) die "--agents: claude, codex o both" ;; esac
case "${IAC:-terraform}" in terraform|opentofu) ;; *) die "--iac: terraform o opentofu" ;; esac
case "$CI" in github|none) ;; *) die "--ci: github o none" ;; esac
[ "$PROVIDERS" = aws ] || die "--providers: nella v1 solo aws"
# ------------------------------------------------------------------ validazione (prima di qualsiasi scrittura)
[ -z "$PROJECT" ] || printf '%s\n' "$PROJECT" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$' || die "--project: kebab-case (a-z, 0-9, trattini), ricevuto '$PROJECT'"
[ -z "$ACCOUNT_ID" ] || printf '%s\n' "$ACCOUNT_ID" | grep -Eq '^[0-9]{12}$' || die "--account-id: 12 cifre, ricevuto '$ACCOUNT_ID'"
printf '%s\n' "$REGION" | grep -Eq '^[a-z]{2}(-[a-z]+)+-[0-9]$' || die "--region: formato tipo eu-south-1, ricevuto '$REGION'"
case "$SCOPE" in local|project|user) ;; *) die "--scope: local, project o user" ;; esac
printf '%s\n' "$ENVS" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*(,[a-z0-9]+(-[a-z0-9]+)*)*$' || die "--envs: nomi kebab-case separati da virgola, ricevuto '$ENVS'"
case "$INFRA_ROOT" in *'|'*|*'&'*|*'\'*) die "--infra-root: caratteri | & \\ non ammessi" ;; esac
for f in "$TARGET/.claude/settings.json" "$TARGET/.codex/hooks.json"; do
  [ -f "$f" ] || continue
  python3 -c 'import json,sys; json.load(open(sys.argv[1], encoding="utf-8"))' "$f" >/dev/null 2>&1 \
    || die "$f non è JSON valido (commenti o virgole finali?): correggilo e rilancia; non ho scritto nulla"
done
want_claude() { [ "$AGENTS" = claude ] || [ "$AGENTS" = both ]; }
want_codex()  { [ "$AGENTS" = codex ]  || [ "$AGENTS" = both ]; }

# ------------------------------------------------------------------ blocchi gestiti in CLAUDE.md / AGENTS.md
write_block() {  # $1 file, $2 sorgente del blocco (vuota = rimuovi)
  python3 - "$1" "$2" <<'PY'
import re, sys, pathlib
path, src = pathlib.Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8") if path.exists() else ""
block = pathlib.Path(src).read_text(encoding="utf-8").strip() + "\n" if src else ""
pat = re.compile(r"<!-- kynfra:start.*?<!-- kynfra:end -->\n?", re.S)
if pat.search(text):
    text = pat.sub(lambda _: block, text)
elif block:
    text = (text.rstrip() + "\n\n" if text.strip() else "") + block
if text.strip():
    path.write_text(text, encoding="utf-8")
elif path.exists():
    path.unlink()
PY
}

merge_codex_hooks() {  # $1 sorgente, $2 destinazione (.codex/hooks.json), $3 remove|add
  python3 - "$1" "$2" "$3" <<'PY'
import json, sys, pathlib
src, dst, mode = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
ours = json.loads(src.read_text(encoding="utf-8"))["hooks"]
cur = json.loads(dst.read_text(encoding="utf-8")) if dst.exists() else {"hooks": {}}
hooks = cur.setdefault("hooks", {})
is_ours = lambda g: any("tools/kynfra/" in h.get("command", "") for h in g.get("hooks", []))
for ev in set(hooks) | set(ours):
    groups = [g for g in hooks.get(ev, []) if not is_ours(g)]
    if mode == "add":
        groups += ours.get(ev, [])
    if groups:
        hooks[ev] = groups
    else:
        hooks.pop(ev, None)
if hooks:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(cur, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
elif dst.exists():
    dst.unlink()
PY
}

# Regole deny di Claude Code: seconda barriera (indipendente dagli hook) contro la modifica di config, kit e impostazioni.
merge_claude_permissions() {  # $1 .claude/settings.json, $2 add|remove
  python3 - "$1" "$2" <<'PY'
import json, sys, pathlib
dst, mode = pathlib.Path(sys.argv[1]), sys.argv[2]
ours = [f"Edit({p})" for p in (".kynfra/**", "/.kynfra/**", "tools/kynfra/**", "/tools/kynfra/**",
                               ".claude/settings.json", "/.claude/settings.json",
                               ".claude/settings.local.json", "/.claude/settings.local.json")]
cur = json.loads(dst.read_text(encoding="utf-8")) if dst.exists() else {}
perms = cur.setdefault("permissions", {})
deny = [r for r in perms.get("deny", []) if r not in ours]
if mode == "add":
    deny += ours
if deny:
    perms["deny"] = deny
else:
    perms.pop("deny", None)
if not perms:
    cur.pop("permissions", None)
if cur:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(cur, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
elif dst.exists():
    dst.unlink()
PY
}

# ------------------------------------------------------------------ disinstallazione
if [ "$UNINSTALL" = 1 ]; then
  info "Rimuovo kynfra da $TARGET"
  [ -f "$TARGET/CLAUDE.md" ] && write_block "$TARGET/CLAUDE.md" ""
  [ -f "$TARGET/AGENTS.md" ] && write_block "$TARGET/AGENTS.md" ""
  rm -rf "$TARGET/.claude/rules/kynfra" "$TARGET/.agents/skills/kynfra-"* "$TARGET/.agents/skills/create-"*"-infra-"* "$TARGET/.codex/agents/kynfra_"*.toml
  [ -f "$TARGET/.claude/settings.json" ] && merge_claude_permissions "$TARGET/.claude/settings.json" remove
  [ -f "$TARGET/.codex/hooks.json" ] && merge_codex_hooks "$KIT_DIR/templates/codex-hooks.json" "$TARGET/.codex/hooks.json" remove
  rm -f "$TARGET/.github/workflows/kynfra-check.yml"
  rm -rf "$TARGET/${KIT_REL:?}"
  [ "$FORCE" = 1 ] && rm -rf "$TARGET/.kynfra"
  if command -v claude >/dev/null && [ "$NO_PLUGIN" = 0 ]; then
    (cd "$TARGET" && claude plugin uninstall kynfra@kynfra --scope "$SCOPE" >/dev/null 2>&1 || true)
  fi
  ok "kynfra rimosso (.kynfra/ e .tflint.hcl conservati; .kynfra/ si elimina con --force)"
  exit 0
fi

# ------------------------------------------------------------------ rilevamento infra_root e progetto
CFG="$TARGET/.kynfra/config.json"
CFG_EXISTS=0
if [ -f "$CFG" ] && [ "$FORCE" = 0 ]; then CFG_EXISTS=1; fi

if [ "$CFG_EXISTS" = 1 ]; then
  # config esistente: è la fonte di verità (infra_root, iac, progetto) per i file generati
  eval "$(python3 - "$CFG" <<'PY'
import json, shlex, sys
try:
    c = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    c = {}
for k, v in (("INFRA_ROOT", c.get("infra_root")), ("IAC", c.get("iac")), ("PROJECT", c.get("project"))):
    if isinstance(v, str) and v:
        print(f"[ -n \"${k}\" ] || {k}={shlex.quote(v)}")
PY
)"
fi
if [ -z "$INFRA_ROOT" ]; then
  if [ -d "$TARGET/.kybes" ] || [ -d "$TARGET/.kyfes" ] || [ -d "$TARGET/infra" ]; then INFRA_ROOT="infra"; else INFRA_ROOT="."; fi
fi
INFRA_ROOT="${INFRA_ROOT%/}"
[ -n "$INFRA_ROOT" ] || INFRA_ROOT="."
case "$INFRA_ROOT" in /*|..|../*|*/..|*/../*) die "--infra-root deve essere una cartella relativa dentro il progetto" ;; esac
case "$IAC" in terraform|opentofu) ;; *) IAC=terraform ;; esac
if [ -z "$PROJECT" ]; then
  PROJECT="$(basename "$TARGET" | python3 -c 'import re,sys; print(re.sub(r"[^a-z0-9]+","-",sys.stdin.read().strip().lower()).strip("-") or "project")')"
fi
HAS_KYBES=0; [ -d "$TARGET/.kybes" ] && HAS_KYBES=1
[ "$INFRA_ROOT" = "." ] || mkdir -p "$TARGET/$INFRA_ROOT"
if [ "$INFRA_ROOT" = "." ]; then PATH_PREFIX=""; else PATH_PREFIX="$INFRA_ROOT/"; fi
info "Progetto: $TARGET — progetto $PROJECT, infra_root $INFRA_ROOT, IaC $IAC, agenti $AGENTS"

# ------------------------------------------------------------------ copia versionata del kit
KIT_DST="$TARGET/$KIT_REL"
if [ "$KIT_DIR" != "$KIT_DST/plugins/kynfra" ]; then
  rm -rf "${KIT_DST:?}"
  mkdir -p "$KIT_DST/plugins" "$KIT_DST/.claude-plugin" "$KIT_DST/.agents/plugins"
  (cd "$KIT_DIR/.." && tar --exclude='__pycache__' -cf - kynfra) | (cd "$KIT_DST/plugins" && tar -xf -)
  cat > "$KIT_DST/.claude-plugin/marketplace.json" <<'EOF'
{
  "name": "kynfra",
  "owner": { "name": "kynfra" },
  "plugins": [{ "name": "kynfra", "source": "./plugins/kynfra", "description": "Know Your Infrastructure: guarded Terraform for AWS." }]
}
EOF
  cat > "$KIT_DST/.agents/plugins/marketplace.json" <<'EOF'
{
  "name": "kynfra",
  "plugins": [{ "name": "kynfra", "source": { "source": "local", "path": "./plugins/kynfra" } }]
}
EOF
  cp "$KIT_DIR/templates/setup.sh" "$KIT_DST/setup.sh" && chmod +x "$KIT_DST/setup.sh"
  ok "kit copiato in $KIT_REL/ (usato da CI, hook Codex e colleghi)"
fi

# ------------------------------------------------------------------ configurazione
if [ "$CFG_EXISTS" = 0 ]; then
  mkdir -p "$TARGET/.kynfra"
  python3 - "$KIT_DIR/templates/kynfra.config.json" "$CFG" "$IAC" "$INFRA_ROOT" "$PROJECT" "$REGION" "$ACCOUNT_ID" "$ENVS" "$HAS_KYBES" <<'PY'
import json, sys, re
tpl, dst, iac, root, project, region, account, envs, kybes = sys.argv[1:10]
cfg = json.load(open(tpl, encoding="utf-8"))
cfg["iac"], cfg["infra_root"], cfg["project"], cfg["region"] = iac, root, project, region
cfg["accounts"] = {"main": {"id": account or "000000000000"}}
names = [e.strip() for e in envs.split(",") if e.strip()]
if not names or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]*", e) for e in names):
    sys.exit("--envs: nomi in minuscolo separati da virgola (es. dev,staging,prod)")
cfg["environments"] = {e: {"account": "main"} for e in names}
if kybes == "1":
    cfg["kybes"] = {"root": ".", "openapi": "schemas/openapi.yaml"}
with open(dst, "w", encoding="utf-8") as fh:
    json.dump(cfg, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PY
  ok ".kynfra/config.json creato"
  [ -n "$ACCOUNT_ID" ] || warn "account AWS non indicato: imposta accounts.main.id in .kynfra/config.json (segnaposto 000000000000)"
  warn "tag Owner e CostCenter vuoti: compilali in .kynfra/config.json (tags)"
else
  info ".kynfra/config.json esistente: non modificato"
fi

# .tflint.hcl nella radice dell'infrastruttura (ruleset AWS dalla versione di versions.json)
TFLINT_CFG="$TARGET/$INFRA_ROOT/.tflint.hcl"
if [ ! -f "$TFLINT_CFG" ] || [ "$FORCE" = 1 ]; then
  RULESET_VER="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tflint_ruleset_aws"]["version"])' "$KIT_DIR/templates/versions.json")"
  sed "s/__RULESET_AWS_VERSION__/$RULESET_VER/g" "$KIT_DIR/templates/tflint.hcl" > "$TFLINT_CFG"
  ok "${PATH_PREFIX}.tflint.hcl creato"
else
  info "${PATH_PREFIX}.tflint.hcl esistente: non modificato"
fi

# .gitignore: binari, virtualenv e plugin installati da tools.py non vanno nel repository
python3 - "$TARGET/.gitignore" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
add = [x for x in (".kynfra/bin/", ".kynfra/venv/", ".kynfra/tflint.d/", "**/.terraform/") if x not in lines]
if add:
    p.write_text("\n".join(lines + add) + "\n", encoding="utf-8")
PY

BLOCK_SRC="$(mktemp)"
trap 'rm -f "$BLOCK_SRC"' EXIT
sed -e "s|__INFRA_ROOT__|$INFRA_ROOT|g" -e "s|__IAC__|$IAC|g" "$KIT_DIR/templates/AGENTS.kynfra.md" > "$BLOCK_SRC"

# ------------------------------------------------------------------ Claude Code
if want_claude; then
  mkdir -p "$TARGET/.claude/rules/kynfra"
  for f in "$KIT_DIR"/templates/rules/*.md; do
    dst="$TARGET/.claude/rules/kynfra/$(basename "$f")"
    if [ ! -f "$dst" ] || [ "$FORCE" = 1 ]; then
      sed -e "s|__PATH_PREFIX__|$PATH_PREFIX|g" -e "s|__INFRA_ROOT__|$INFRA_ROOT|g" "$f" > "$dst"
    fi
  done
  write_block "$TARGET/CLAUDE.md" "$BLOCK_SRC"
  merge_claude_permissions "$TARGET/.claude/settings.json" add
  ok "Claude Code: .claude/rules/kynfra/, blocco in CLAUDE.md, regole deny in .claude/settings.json"
  if [ "$NO_PLUGIN" = 0 ]; then
    if command -v claude >/dev/null; then
      bash "$KIT_DST/setup.sh" "$SCOPE" >/dev/null 2>&1 && ok "Claude Code: plugin kynfra registrato (scope $SCOPE)" \
        || warn "registrazione del plugin non riuscita: esegui $KIT_REL/setup.sh"
    else
      warn "comando 'claude' non trovato: installa il plugin con /plugin marketplace add en1-gma/kynfra"
    fi
  fi
fi

# ------------------------------------------------------------------ Codex
if want_codex; then
  write_block "$TARGET/AGENTS.md" "$BLOCK_SRC"
  mkdir -p "$TARGET/.agents/skills" "$TARGET/.codex/agents"
  for s in "$KIT_DIR"/skills/*/; do
    [ -d "$s" ] || continue
    name="$(basename "$s")"
    case "$name" in kynfra-*|create-*-infra-*) ;; *) continue ;; esac
    rm -rf "$TARGET/.agents/skills/$name"
    cp -R "$s" "$TARGET/.agents/skills/$name"
  done
  for a in "$KIT_DIR"/templates/codex-agents/*.toml; do
    cp "$a" "$TARGET/.codex/agents/$(basename "$a")"
  done
  merge_codex_hooks "$KIT_DIR/templates/codex-hooks.json" "$TARGET/.codex/hooks.json" add
  ok "Codex: blocco in AGENTS.md, .agents/skills/{kynfra-*,create-*-infra-*}, .codex/agents/kynfra_*.toml, .codex/hooks.json"
  info "Codex: rendi il progetto trusted e approva gli hook di kynfra alla prima apertura"
fi

# ------------------------------------------------------------------ CI
if [ "$CI" = github ]; then
  mkdir -p "$TARGET/.github/workflows"
  WF="$TARGET/.github/workflows/kynfra-check.yml"
  if [ ! -f "$WF" ] || [ "$FORCE" = 1 ]; then
    sed -e "s/__IAC__/$IAC/g" "$KIT_DIR/templates/ci/kynfra-check.yml" > "$WF"
    ok "CI: .github/workflows/kynfra-check.yml"
  fi
fi

ok "kynfra installato. Controllo completo: python3 -B $KIT_REL/plugins/kynfra/scripts/arch_check.py ."
info "Strumenti esterni (non scaricati dall'installer): /kynfra:tools oppure python3 -B $KIT_REL/plugins/kynfra/scripts/tools.py status"
