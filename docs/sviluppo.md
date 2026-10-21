# Sviluppare il kit

```text
kynfra/
├── .claude-plugin/marketplace.json        ← marketplace Claude Code
├── .agents/plugins/marketplace.json       ← marketplace Codex
├── .github/workflows/kit-tests.yml        ← CI del kit
├── install.sh                             ← wrapper dell'installer
├── plugins/kynfra/
│   ├── .claude-plugin/plugin.json         ← manifest Claude Code
│   ├── .codex-plugin/plugin.json          ← manifest Codex
│   ├── skills/                            ← kynfra-architecture (+ references/aws.md), -init, -plan, -review, -tools, create-<pattern>-infra-aws
│   ├── agents/                            ← architect, implementer, reviewer (Claude Code)
│   ├── hooks/hooks.json                   ← hook comuni (Claude Code e Codex)
│   ├── scripts/                           ← hcl, rules*, kybes, hook, bash_guard, shell_*, arch_check, external, tools, generate
│   ├── templates/                         ← config, blocco AGENTS/CLAUDE, regole per percorso, CI, agenti e hook Codex,
│   │                                         versions.json, tools-catalog.json, scanner-baseline.json, tflint.hcl, aws/
│   └── install.sh
├── tests/hooks/                           ← unittest: parser, regole, hook, guard Bash, stop gate, generatore, tools, installer, docs
├── tests/patterns/test_patterns.py        ← harness dei pattern (genera e controlla ogni pattern)
├── tests/fixtures/kybes-repo/             ← progetto kybes di esempio per il pattern backend
└── docs/
```

Solo libreria standard Python, **compatibile con 3.10** (la CI lo verifica con una gamba dedicata). Messaggi all'utente e docstring in italiano.

## Verifica

```bash
bash tests/run.sh                          # unittest di tests/hooks (nessuno strumento esterno, nessuna rete)
bash tests/run.sh --patterns               # + tutti i pattern di patterns.json
bash tests/run.sh --patterns "network spa" # + solo alcuni pattern
```

`tests/run.sh` lancia sempre prima gli unittest di `tests/hooks/` e, con `--patterns`, l'harness di `tests/patterns/`. Tra i test degli hook, `test_docs.py` tiene coerenti documentazione e prodotto: ogni regola di `DEFAULT_RULES` compare in `docs/controlli.md`, ogni chiave di config in `docs/configurazione.md`, ogni pattern ha la sua pagina in `docs/pattern/` e il suo comando nel README, ogni skill è nel README, i link relativi risolvono e la matrice del workflow elenca esattamente i pattern di `patterns.json`.

## L'harness dei pattern

Ogni pattern di `templates/aws/patterns.json` (`bootstrap` compreso) è generato in una cartella vuota con una config di riferimento (ambienti `dev` e `prod`, più i pattern richiesti dai suoi `requires`) e deve:

1. generare file, senza `missing_requires`;
2. passare `arch_check` a zero finding, **avvisi compresi** (modalità strict);
3. se gli strumenti sono disponibili: `terraform fmt -check`, `init -backend=false` e `validate` per stack, `tflint`, `checkov` con la baseline del kit (le stesse `external_steps` dello stop gate).

I pattern `single_env` (`spa`, `elb`) si generano un ambiente per comando; il backend si genera nella copia della fixture `tests/fixtures/kybes-repo` con `kybes.root = "."` e `requires` estesi da `requires_with_workloads` (la fixture ha microservizi e job). Gli input richiesti senza default usano il campo `example` di `patterns.json` (anche un dizionario per ambiente).

| Variabile | Effetto |
|---|---|
| `KYNFRA_PATTERNS="p1 p2"` | limita i pattern (è ciò che fa `--patterns p1 p2`) |
| `KYNFRA_REQUIRE_TOOLS=1` | gli strumenti esterni sono obbligatori: uno strumento mancante è un errore (CI) |
| `KYNFRA_TOOLS_PROJECT=<dir>` | cerca i binari verificati sul registro di `<dir>/.kynfra` (e i plugin di TFLint) invece che nel progetto temporaneo |

Senza `KYNFRA_REQUIRE_TOOLS` e senza alcun binario risolvibile l'harness controlla solo `arch_check`. **`VARIANTS`** (in `test_patterns.py`) aggiunge combinazioni di input da verificare con gli stessi controlli: la SPA con zona esistente e `/api/*`, l'ELB come NLB interno o raggiungibile solo da CloudFront, l'EKS con endpoint pubblico a CIDR espliciti, il backend con authorizer Cognito e RDS Proxy MySQL, i segreti con replica e lettori (la chiave `_tfvars` sostituisce testo nei `terraform.tfvars` generati per strutture che il generatore non sa passare).

### Strumenti reali in locale

Il repository del kit fa da progetto per `tools.py` (senza `.kynfra/config.json` il progetto è la cartella corrente; `.kynfra/` è ignorata da git, il kit non è un progetto kynfra):

```bash
python3 -B plugins/kynfra/scripts/tools.py install terraform --approved-by "Il Tuo Nome"
python3 -B plugins/kynfra/scripts/tools.py install tflint --approved-by "Il Tuo Nome"
python3 -B plugins/kynfra/scripts/tools.py install tflint-ruleset-aws --approved-by "Il Tuo Nome"
python3 -B plugins/kynfra/scripts/tools.py install checkov --approved-by "Il Tuo Nome"
KYNFRA_TOOLS_PROJECT=$PWD KYNFRA_REQUIRE_TOOLS=1 bash tests/run.sh --patterns spa
```

Un'installazione per strumento, come sempre (vedi [strumenti](strumenti.md)). `terraform init -backend=false` scarica i provider: per non riscaricarli a ogni pattern esporta `TF_PLUGIN_CACHE_DIR` (una cartella esistente).

## La CI del kit

`.github/workflows/kit-tests.yml`, con `permissions: contents: read` e nessuna credenziale cloud (niente `id-token`, nessun secret):

| Job | Cosa fa |
|---|---|
| `hooks` | `bash tests/run.sh`, due gambe: Python **3.10** (la versione minima supportata) e **3.12** |
| `patterns` | matrice con **esattamente** le chiavi di `patterns.json` (`backend`, `bootstrap`, `ecr`, `eks`, `elb`, `network`, `secrets`, `spa`), `fail-fast: false`. Ogni job installa con `tools.py install <strumento> --approved-by ci` Terraform, TFLint, il ruleset AWS e Checkov (uno step per strumento, versioni di `versions.json`, nel checkout, che fa da progetto) e lancia `KYNFRA_TOOLS_PROJECT=$GITHUB_WORKSPACE KYNFRA_REQUIRE_TOOLS=1 bash tests/run.sh --patterns <p>`. `TF_PLUGIN_CACHE_DIR` è in cache con `actions/cache`, con chiave sulla versione dei provider |

Un pattern nuovo in `patterns.json` fa fallire `test_workflow_matrix_matches_patterns` finché non è nella matrice. Il template per i progetti utente è `templates/ci/kynfra-check.yml` (stessi controlli su `infra_root`, stesso principio: nessun accesso al cloud).

## Aggiungere una regola

1. Aggiungi il default in `DEFAULT_RULES` (`rules.py`) e il controllo in `rules_common.py` (trasversale) o `rules_aws.py` (`AWS_RULES` per file, `AWS_PROJECT_RULES` se correla più risorse); il nome della funzione in snake_case è il nome della regola. Messaggi in italiano, con la correzione.
2. Aggiungi almeno un caso conforme e uno non conforme in `tests/hooks/test_rules_*.py`; un bypass o un falso positivo corretto va in un test di regressione, perché non torni.
3. Documentala in `docs/controlli.md` (il test `test_docs_cover_rules` fallisce altrimenti) e, se cambia il modo di scrivere codice, in `skills/kynfra-architecture`.
4. Verifica che tutti i pattern restino a zero violazioni: `bash tests/run.sh --patterns`.

## Aggiungere o aggiornare un pattern

Modulo in `templates/aws/modules/<pattern>/`, stack in `templates/aws/stacks/<stack>/`, voce in `patterns.json` (`description`, `requires`, `inputs` con `example` per i richiesti, `env_defaults`, `stacks`, `shared_stacks`, `next_steps`), skill `create-<pattern>-infra-aws`, pagina in `docs/pattern/<pattern>.md`, riga nel README, voce nella matrice del workflow. I template usano solo segnaposto `{{ nome }}` senza logica; le versioni vengono da `versions.json` (placeholder `*_constraint`, `*_chart_version`). Ogni modifica deve lasciare verdi `arch_check --strict` e gli strumenti reali; i controlli dello scanner che un modulo non soddisfa per scelta vanno in `scanner-baseline.json` con un motivo, limitati a id, percorso e ambiente.

## Aggiornare le versioni

`versions.json` è l'unico punto delle versioni (Terraform, OpenTofu, provider, TFLint e ruleset, Checkov, Trivy, chart Helm): contiene data e fonte della verifica. Dopo averlo cambiato rigenera i lock e rilancia l'harness con gli strumenti reali. Evita le release pubblicate lo stesso giorno.
