---
name: kynfra-init
description: Set up kynfra in the current project for Claude Code and/or Codex (config, path rules, CLAUDE.md/AGENTS.md block, Codex skills/agents/hooks, CI, tflint config). Use when the user asks to install, initialise, set up or update kynfra in a repository.
---

# Installare kynfra in un progetto

Finché `.kynfra/config.json` non esiste, ogni hook di kynfra è un no-op in questo repository.

1. Trova l'installer: `<radice del plugin>/install.sh`, dove la radice del plugin sta due cartelle sopra quella di questa skill (`<radice>/skills/kynfra-init/`). In un progetto dove kynfra è già installato (per esempio Codex che legge `.agents/skills/`) usa `tools/kynfra/plugins/kynfra/install.sh`; altrimenti clona `https://github.com/en1-gma/kynfra` e usa il suo `install.sh`.
2. Rileva ciò che puoi dal repository: `.kybes/` o `.kyfes/` o `infra/` (allora `infra_root` è `infra`, altrimenti `.`), file `.tf` esistenti, nome della cartella (progetto), `git config user.name`. Chiedi all'utente, **in un solo giro di domande**, solo ciò che manca:
   - nome del progetto (kebab-case);
   - ambienti (default `dev,staging,prod`) e regione (default `eu-south-1`);
   - ID dell'account AWS (12 cifre) — non è un segreto, ma se l'utente non lo dice lascia il segnaposto e riportalo;
   - IaC: `terraform` (default) o `opentofu`;
   - agenti da configurare: `claude`, `codex` o `both` (default `both`);
   - CI: `github` (default) o `none`.
3. Lancia l'installer dalla radice del progetto:

   ```bash
   bash "<radice del plugin>/install.sh" --target . --project <nome> --envs dev,staging,prod --region eu-south-1 \
     [--account-id <12 cifre>] [--iac terraform|opentofu] [--infra-root <dir>] --agents <claude|codex|both> [--ci github|none]
   ```

   Altre opzioni: `--providers aws`, `--scope local|project|user` (registrazione del plugin), `--no-plugin`. È idempotente: non sovrascrive configurazione, regole o `.tflint.hcl` esistenti (solo con `--force`), aggiorna il kit e i blocchi `kynfra` in `CLAUDE.md` e `AGENTS.md`. Non scrive file IaC, non lancia Terraform e non scarica strumenti.
4. Riporta in poche righe cosa è stato creato:
   - `.kynfra/config.json` (progetto, `infra_root`, ambienti, account, tag, regole, stop gate) e `.tflint.hcl` in `infra_root`;
   - `tools/kynfra/`: copia versionata del kit, usata da CI, colleghi e hook di Codex;
   - Claude Code: `.claude/rules/kynfra/`, blocco in `CLAUDE.md`, regole `permissions.deny` in `.claude/settings.json` (niente `Edit` su `.kynfra/**`, `tools/kynfra/**`, `.claude/settings*.json`; le impostazioni esistenti restano);
   - Codex: blocco in `AGENTS.md`, `.agents/skills/` (le skill `kynfra-*` e i comandi `create-*-infra-aws`), `.codex/agents/kynfra_*.toml`, `.codex/hooks.json` (Codex chiede di rivedere e approvare gli hook al primo avvio; il progetto deve essere trusted);
   - `.github/workflows/kynfra-check.yml` (senza accesso al cloud);
   - `.gitignore` aggiornato per `.kynfra/bin/`, `.kynfra/venv/`, `.kynfra/tflint.d/`, `**/.terraform/`.
5. Ricorda le cose da completare a mano: `accounts.main.id` se è rimasto il segnaposto `000000000000`, i tag `Owner` e `CostCenter` in `tags`.
6. Controlla gli strumenti esterni con `python3 -B tools/kynfra/plugins/kynfra/scripts/tools.py status` e, se ne mancano, proponi la skill `kynfra-tools` (`/kynfra:tools`): si installano uno strumento alla volta, con l'approvazione dell'utente per ciascuno.
7. Suggerisci il passo successivo: descrivere cosa ospitare e pianificarlo con l'agente `kynfra:architect` (Claude Code) o `$kynfra-plan` (Codex), poi `/kynfra:create-<pattern>-infra-aws`.

Non modificare `.kynfra/config.json` dopo l'installazione: è protetto e lo cambia solo l'utente. Lo stesso vale per `tools/kynfra/`, `.terraform.lock.hcl`, le impostazioni e gli hook dell'agente, le regole, le skill, gli agenti e il workflow CI di kynfra; gli hook rifiutano anche `install.sh --force` e `--uninstall` dalla shell dell'agente, quindi chiedi all'utente di eseguirli.
