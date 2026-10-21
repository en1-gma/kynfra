# kynfra in Codex

Codex legge gli stessi file di Claude Code dove il formato è comune, e file propri dove non lo è.

| Elemento | Dove | Note |
|---|---|---|
| Plugin | `plugins/kynfra/.codex-plugin/plugin.json` + `.agents/plugins/marketplace.json` | `codex plugin marketplace add en1-gma/kynfra`, poi `codex plugin add kynfra@kynfra` |
| Skill | `plugins/kynfra/skills/*` (dal plugin) o `.agents/skills/kynfra-*` e `.agents/skills/create-*-infra-*` (nel progetto) | `$kynfra-architecture`, `$kynfra-plan`, `$kynfra-review`, `$kynfra-init`, `$kynfra-tools` e i sette `$create-<pattern>-infra-aws` |
| Istruzioni | blocco gestito in `AGENTS.md` | lo stesso testo del blocco in `CLAUDE.md` |
| Agenti | `.codex/agents/kynfra_architect.toml`, `kynfra_implementer.toml`, `kynfra_reviewer.toml` | equivalenti di `kynfra:architect`, `kynfra:implementer`, `kynfra:reviewer` |
| Hook | `plugins/kynfra/hooks/hooks.json` (plugin) o `.codex/hooks.json` (progetto) | stessi script: `SessionStart`, `PreToolUse` su `apply_patch\|Write\|Edit` e sulla shell (`Bash\|shell\|exec_command\|local_shell`), `PostToolUse`, `Stop` |

L'installer scrive sempre i file di progetto (`AGENTS.md`, `.agents/skills`, `.codex/agents`, `.codex/hooks.json`) che puntano alla copia versionata del kit in `tools/kynfra/`: chi clona il repository ha regole, agenti e controlli senza installare nulla. Gli hook di progetto invocano gli script con `python3 -B "$(git rev-parse --show-toplevel)/tools/kynfra/plugins/kynfra/scripts/…"`; l'installer fonde i propri hook in un `.codex/hooks.json` esistente senza toccare i tuoi, e `--uninstall` li rimuove.

## Fiducia

Codex carica configurazione e hook di progetto solo se il progetto è *trusted*, e chiede di rivedere gli hook nuovi o modificati prima di eseguirli. Le skill si caricano comunque. Alla prima apertura: rendi trusted il progetto e approva gli hook `kynfra`.

## Differenze rispetto a Claude Code

- Codex modifica i file con `apply_patch`: per ogni `Update File` l'hook ricostruisce il file risultante applicando gli hunk al file su disco e applica le stesse regole di Claude Code (se il contesto non si trova, valuta le righe aggiunte). `Delete File` e `Move to` su file protetti sono negati.
- Le scritture da shell (es. `cat > infra/envs/dev/x.tf`, `sed -i`, `git apply`) le intercetta `bash_guard.py`, con un controllo euristico: lo stop gate e la CI eseguono comunque `arch_check` sull'intero progetto.
- L'installer scrive le regole `permissions.deny` solo per Claude Code: in Codex i file protetti (`.kynfra/`, `tools/kynfra/`, `.codex/hooks.json`, `.codex/config.toml`, `.codex/agents/kynfra_*`, …) sono difesi solo dagli hook e dalla CI.
- `.codex/hooks.json` registra `Stop` ma non `SubagentStop`.
- Codex non supporta `permissionDecision: "ask"` negli hook `PreToolUse`: `tools.py install` viene negato con il comando da far eseguire all'utente nel suo terminale (in Claude Code la guardia risponde `ask`).
- Le regole per percorso di Claude Code (`.claude/rules/kynfra/*.md`) non hanno un equivalente diretto: in Codex il contenuto è nella skill e in `AGENTS.md`.
- Come per Claude Code, la barriera decisiva contro un `apply` è l'assenza di credenziali cloud nella sessione dell'agente (vedi [controlli](controlli.md#un-controllo-euristico)).
