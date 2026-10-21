# Configurazione: `.kynfra/config.json`

Creato dall'installer, protetto dagli hook (scritture, `apply_patch` e comandi shell, con qualunque combinazione di maiuscole nel percorso) e, in Claude Code, dalle regole `permissions.deny` che l'installer aggiunge a `.claude/settings.json`: **lo modifica solo l'utente**. L'agente non può cambiare severità, eccezioni o comandi dello stop gate per far passare il proprio lavoro.

In un monorepo ogni progetto ha la sua `.kynfra/config.json`: gli hook usano quella più vicina al file scritto, e lo stop gate lanciato dalla radice controlla i progetti kynfra che trova sotto il cwd.

```json
{
  "iac": "terraform",
  "providers": ["aws"],
  "infra_root": "infra",
  "project": "acme",
  "region": "eu-south-1",
  "accounts": { "main": { "id": "123456789012" } },
  "environments": { "dev": { "account": "main" }, "staging": { "account": "main" }, "prod": { "account": "main" } },
  "tags": { "Owner": "platform", "CostCenter": "cc-001" },
  "scanner": "checkov",
  "rules": { "variables-typed": "block", "region-pinning": "off" },
  "exceptions": [
    { "rule": "sg-open", "path": "envs/dev/elb/**", "reason": "demo pubblica per il cliente X", "expires": "2026-12-31" }
  ],
  "stop_gate": { "enabled": true, "only_if_changes": true, "max_blocks": 3, "commands": [] },
  "kybes": { "root": ".", "openapi": "schemas/openapi.yaml" },
  "public_routes": ["GET /v1/health"]
}
```

## Chiavi

| Chiave | Default | Significato |
|---|---|---|
| `iac` | `terraform` | `terraform` oppure `opentofu`: cambia i comandi di stop gate e CI (`terraform`/`tofu`), non i file |
| `providers` | `["aws"]` | piattaforme attive; nella v1 solo `aws`. Determina quali regole di piattaforma (`rules_aws.py`) si applicano |
| `infra_root` | `.` | cartella dell'infrastruttura, relativa al progetto (`infra` in un repository kybes/kyfes). Un valore vuoto, assoluto o che esce dal progetto diventa `.`. Le regole si applicano solo ai file sotto questa cartella |
| `project` | `""` | nome del progetto in kebab-case: prefisso dei nomi (`<progetto>-<env>-…`), delle chiavi di stato e del bucket dello stato |
| `region` | `eu-south-1` | regione AWS di default (Milano); finisce nei `tfvars`, mai nei moduli |
| `accounts` | `{}` | account AWS, per nome: `{"main": {"id": "123456789012"}}` (vedi [account](account.md)). Ogni stack riceve `account_id` dai `tfvars` e lo usa in `allowed_account_ids` |
| `environments` | `dev`, `staging`, `prod` su `main` | ambienti ammessi e account di ciascuno. `folder-layout` rifiuta cartelle `envs/<x>` con `x` non dichiarato (tranne `shared`). `"prod": true` marca un ambiente di produzione (es. `"production": {"account": "main", "prod": true}`): le regole "solo prod" e i default prod-restrittivi del generatore valgono per ogni ambiente marcato; un ambiente chiamato `prod` lo è anche senza flag, salvo `"prod": false`. L'installer imposta il flag con `--prod-envs` |
| `tags` | `{}` | valori dei tag obbligatori `Owner` e `CostCenter` (gli altri sono calcolati: `Project`, `Environment`, `ManagedBy = "kynfra"`). L'installer li compila con `--owner` e `--cost-center`; vuoti, `generate.py` si ferma |
| `scanner` | `checkov` | `checkov` o `trivy`. Con Checkov la baseline del kit si applica sull'output JSON; per Trivy non c'è baseline |
| `config_problems` | calcolata | non si scrive: l'elenco dei valori di tipo sbagliato trovati nella config (tornati al default, mai a regole spente), che `check_project` riporta come avvisi `config` |
| `rules` | vedi [controlli](controlli.md) | `block`, `warn` oppure `off` per regola; i nomi sconosciuti sono ignorati |
| `exceptions` | `[]` | eccezioni con scadenza (sotto) |
| `stop_gate.enabled` | `true` | attiva il controllo finale |
| `stop_gate.only_if_changes` | `true` | salta il controllo solo se `git status` è pulito e `HEAD` non è cambiato dall'inizio della sessione (senza baseline: nessun commit non pubblicato su un remote) |
| `stop_gate.max_blocks` | `3` | blocchi di fila nella stessa catena di stop, poi chiusura consentita con l'avviso "NON è conforme" |
| `stop_gate.commands` | `[]` | comandi aggiuntivi eseguiti nella radice del progetto (timeout 600 s ciascuno) |
| `literal_reuse.max_duplicate_ratio` | `0.10` | quota massima di letterali di dominio duplicati prima che `literal-reuse` blocchi allo stop gate |
| `literal_reuse.min_values` | `20` | sotto questo numero di letterali la soglia non si applica (i singoli avvisi `warn` restano) |
| `exclude` | `[]` (+ `**/.terraform/**`) | glob di percorsi (relativi al progetto) esclusi dalla scansione |
| `kybes` | assente | presente solo nei repository kybes: `root` (cartella del progetto kybes, relativa al progetto; l'installer scrive `.`) e `openapi` (default `schemas/openapi.yaml`). Abilita `api-coverage` e il pattern `backend`; senza questa sezione `/kynfra:create-backend-infra-aws` non parte |
| `public_routes` | `[]` | operazioni dell'API che possono restare senza authorizer, nel formato `"METODO /percorso"` (es. `"GET /v1/health"`). Serve anche `security: []` sull'operazione nello schema OpenAPI (vedi [pattern backend](pattern/backend.md)) |

## Eccezioni

Nessuna soppressione inline: `checkov:skip`, `trivy:ignore`, `tflint-ignore` (e `tfsec:ignore`, `kics scan ignore`) sono rifiutati da `scanner-suppression`. Un'eccezione è una voce di `exceptions`:

```json
{ "rule": "sg-open", "path": "envs/dev/elb/**", "resource": "aws_security_group_rule.ssh", "reason": "motivo obbligatorio", "expires": "2026-12-31" }
```

| Campo | Obbligatorio | Significato |
|---|---|---|
| `rule` | sì | nome della regola (vedi [controlli](controlli.md)) |
| `path` | sì | glob relativo a `infra_root` (`envs/dev/**`, `modules/spa/*.tf`) |
| `resource` | no | indirizzo della risorsa (`aws_s3_bucket.site`); se presente, l'eccezione vale solo per quella |
| `reason` | sì | perché; compare nel messaggio quando l'eccezione scade |
| `expires` | sì | data `YYYY-MM-DD`: **dal giorno dopo la regola torna a bloccare**, con data e motivo nel messaggio |

Una voce malformata (campo mancante, data non valida) è ignorata e genera un avviso `config`, uno per voce. Tre regole non sono mai escludibili: `hcl-syntax`, `protected-files` e `config`. Le eccezioni valgono per le regole di kynfra; i controlli degli strumenti esterni si gestiscono con la baseline (sotto), non con `exceptions`.

## Baseline dello scanner

La baseline dello scanner vive nel **kit** (`plugins/kynfra/templates/scanner-baseline.json`, copiato in `tools/kynfra/`, protetto), non nel progetto, ed è la stessa con cui la CI del kit verifica i template. Per Checkov, `external.py` esegue lo scanner con output JSON e filtra i controlli falliti: restano errori solo quelli **non** coperti da una voce. Niente `--skip-check`, perché la baseline è per controllo, file e ambiente.

```json
{
  "checkov": [
    {
      "id": "CKV_AWS_18",
      "envs": "*",
      "paths": ["bootstrap/**"],
      "reason": "Bucket dello stato: il log di accesso richiederebbe un secondo bucket creato prima dello stato stesso."
    }
  ]
}
```

| Campo | Significato |
|---|---|
| `id` | identificativo del controllo dello scanner (voci senza `id` ignorate) |
| `envs` | `"*"` oppure lista di ambienti (`["dev", "staging"]`); l'ambiente è quello dello stack (`envs/<env>/…`). Fuori dagli stack (`modules/`, `bootstrap/`) l'ambiente non è noto e valgono solo le voci con `"*"` |
| `paths` | glob relativi a `infra_root` (default `["**"]`) |
| `reason` | motivo, obbligatorio per convenzione: ogni voce dice perché il controllo non si applica |

Un controllo fallito è escluso solo se **id, percorso e ambiente** combaciano. Esempi di voci del kit: i tre controlli sul bucket dello stato (`CKV_AWS_18`, `CKV_AWS_144`, `CKV2_AWS_62`, solo `bootstrap/**`), le zone di disponibilità della rete (`CKV_AWS_394`), la retention dei flow log in dev e staging (`CKV_AWS_338`), la deletion protection del load balancer imposta da validazione del modulo (`CKV_AWS_150`). Le eccezioni del progetto non toccano la baseline: sono l'unico strumento che l'utente ha per le regole di kynfra.
