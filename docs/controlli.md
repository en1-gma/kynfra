# Controlli automatici

kynfra applica le regole in tre momenti, con lo stesso motore (`plugins/kynfra/scripts/rules.py`, `rules_common.py`, `rules_aws.py`; solo libreria standard Python).

| Momento | Script | Claude Code | Codex |
|---|---|---|---|
| inizio sessione | `session_start.py` (registra `HEAD` come baseline della sessione) | `SessionStart` | `SessionStart` |
| prima di ogni scrittura | `pre_write.py` | `PreToolUse` su `Write\|Edit\|MultiEdit\|NotebookEdit` | `PreToolUse` su `apply_patch` (e `Write\|Edit`) |
| prima di ogni comando shell | `bash_guard.py` | `PreToolUse` su `Bash` | `PreToolUse` su `Bash\|shell\|exec_command\|local_shell` |
| dopo ogni scrittura | `post_edit.py` (avvisi all'agente) | `PostToolUse` | `PostToolUse` |
| prima di chiudere | `stop_gate.py` (`arch_check` + strumenti esterni + comandi) | `Stop`, `SubagentStop` | `Stop` |
| in CI | `arch_check.py --strict --external` | workflow `kynfra-check.yml` | idem |

Senza `.kynfra/config.json` ogni hook non fa nulla: il plugin si può tenere installato anche in progetti che non lo usano. Il progetto si cerca partendo dal file scritto, non dal cwd.

## Cosa valuta `pre_write.py`

- Il file **risultante**, non solo il frammento: per `Write`, `Edit`, `MultiEdit` e `apply_patch` le regole girano sul contenuto finale. Togliere `encrypt = true` da un backend con un `Edit` viene quindi visto anche se il frammento nuovo è innocuo.
- **Solo ciò che la modifica introduce**: una violazione già presente prima (stessa regola sulla stessa riga di codice) non blocca un edit non correlato; la segnalano lo stop gate e la CI.
- Le regole che correlano più risorse (il bucket e il suo `aws_s3_bucket_public_access_block`, i toggle di prod) girano solo sull'insieme del progetto, cioè nello stop gate e in CI: in `pre_write` un file si vede da solo e l'assenza di una risorsa compagna non è ancora un errore.
- Percorsi canonici: su filesystem case-insensitive (macOS, Windows) `.Kynfra/config.json` viene riportato al nome reale prima delle regole.
- Commenti: ignorati dal parser, salvo `scanner-suppression` che li legge apposta.

## Regole

Le severità si cambiano per regola in `.kynfra/config.json` (`rules`, vedi [configurazione](configurazione.md)); le eccezioni hanno scadenza. Le regole `variables-typed`, `region-pinning` e `literal-reuse` sono `warn`; `config` è `warn`; tutte le altre `block`.

### Trasversali

| Regola | Default | Cosa rifiuta | Come correggere |
|---|---|---|---|
| `protected-files` | block | `.kynfra/`, `tools/kynfra/`, `.codex/hooks.json`, `.codex/config.toml`, `.codex/agents/kynfra_*`, `.claude/settings.json` e `.claude/settings.local.json` (`disableAllHooks` spegnerebbe gli hook), `.claude/rules/kynfra/`, `.agents/skills/kynfra-*`, `.github/workflows/kynfra-check.yml`, `.git/hooks/`, `.git/config`, hook e config di sottomoduli e worktree, `.terraform.lock.hcl` sotto `infra_root` | chiedi all'utente; il lock lo rigenera solo `terraform init` (stop gate o utente) |
| `config` | warn | voce di `exceptions` malformata (mancano `rule`, `path`, `reason` o `expires`, o la data non è `YYYY-MM-DD`): ignorata | correggi la voce (la modifica l'utente) |
| `folder-layout` | block | file IaC fuori da `bootstrap/`, `modules/<pattern>/`, `envs/<env>/<stack>/`, `envs/shared/<stack>/`, `native/<pattern>/`; nomi non kebab-case; ambienti non dichiarati in config | sposta il file nella struttura canonica; un ambiente nuovo lo aggiunge l'utente alla config |
| `hcl-syntax` | block | file che il parser non legge per intero. **Fail closed**: un parser che non capisce non significa "nessuna violazione" | correggi la sintassi; i guardrail non possono verificare ciò che non leggono |
| `remote-state` | block | backend locale fuori da `bootstrap/`; backend `s3` senza `encrypt = true` o `use_lockfile = true` | `backend "s3"` con `encrypt = true`, `use_lockfile = true` e chiave `<progetto>/<env>/<stack>.tfstate` |
| `version-pinning` | block | `required_version` senza `~>`; provider senza `version` o con vincolo aperto (`>= 5`); moduli senza versione fissa (git senza `?ref=` a un tag o commit, registry senza `version`, sorgente non letterale) | `~> X.Y`; meglio ancora un modulo locale in `modules/` |
| `static-credentials` | block | `access_key`, `secret_key`, token, `client_secret`, `password` letterali (o `var.*`/`local.*`) nei provider, nei `tfvars` e nelle variabili con default. Un riferimento a un `data` source (token di breve durata, es. EKS) è ammesso | profilo, SSO o OIDC |
| `secrets` | block | segreti in chiaro in `.tf`, `.tfvars`, `native/` (token noti, `password = "…"`, connection string con credenziali, `secret_string`/`secret_binary` letterali); variabili riservate senza `sensitive = true` o con un default | contenitore `aws_secretsmanager_secret` con il valore inserito fuori da Terraform; `var.*` `sensitive` verso un argomento write-only (`*_wo`); vedi [segreti](segreti.md) |
| `required-tags` | block | provider `aws` senza `default_tags` completi (`Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy = "kynfra"`) con chiavi letterali | `default_tags { tags = { Project = …, … } }` |
| `account-guard` | block | provider `aws` negli stack senza `allowed_account_ids` | `allowed_account_ids = [var.account_id]`: un `apply` sull'account sbagliato fallisce |
| `scanner-suppression` | block | commenti `checkov:skip`, `trivy:ignore`, `tflint-ignore`, `tfsec:ignore`, `kics scan ignore` | togli il commento e chiedi all'utente un'eccezione in config (`exceptions`) |
| `no-provisioners` | block | `local-exec`, `remote-exec`, `provisioner "file"` e `data "external"`: codice fuori dal controllo di Terraform | risorse native del provider (`user_data`, SSM, cloud-init) |
| `native-params` | block | nei template in `native/` (CloudFormation YAML/JSON, Bicep): parametri senza `Type`; parametri riservati con default, senza `NoEcho: true` o senza `@secure()` | tipizza il parametro, togli il default, `NoEcho`/`@secure()`; il valore arriva da un secret manager |
| `variables-typed` | warn | variabile senza `type` o senza `description` | dichiara tipo e descrizione |
| `region-pinning` | warn | regione o ID account scritti come letterali nei moduli | variabile dai `tfvars` dell'ambiente, `var.account_id`, `data.aws_caller_identity` |
| `literal-reuse` | warn | stesso letterale di dominio (CIDR, domini, nomi, porte) ripetuto in più file di `modules/` ed `envs/`. Allo stop gate **blocca** se la quota di occorrenze duplicate supera `literal_reuse.max_duplicate_ratio` (10%) con almeno `min_values` (20) valori; i valori nei `*.tfvars` sono definizioni e non contano | un solo punto in `locals` o variabile, poi referenziato; `arch_check` stampa il rapporto a ogni esecuzione |

### AWS

| Regola | Default | Cosa rifiuta | Come correggere |
|---|---|---|---|
| `s3-private` | block | ACL pubbliche (`public-read`, grant ad `AllUsers`/`AuthenticatedUsers`); public access block incompleto (i 4 flag `true` letterali); bucket senza public access block, senza cifratura, senza policy TLS only (Deny su `s3:*` con `aws:SecureTransport = "false"`), senza versioning | `aws_s3_bucket_public_access_block`, `_server_side_encryption_configuration`, `_policy`, `_versioning` che referenziano il bucket (`bucket = aws_s3_bucket.x.id`); contenuti serviti da CloudFront con OAC |
| `cloudfront-https` | block | `viewer_protocol_policy = "allow-all"`; TLS minimo sotto `TLSv1.2_2021` o certificato di default di CloudFront; origin S3 con OAI o endpoint website; origin S3 senza `origin_access_control_id`; distribuzione senza response headers policy, senza log di accesso, **senza WAF in prod** | `redirect-to-https`, `minimum_protocol_version = "TLSv1.2_2021"` con certificato ACM, OAC, `aws_cloudfront_response_headers_policy`, `logging_config` o log v2, `web_acl_id = var.waf_enabled ? … : null` e `waf_enabled = true` nei `tfvars` di prod |
| `lb-https` | block | listener HTTP che non fa redirect; regole su listener HTTP; `ssl_policy` fuori dalla famiglia `ELBSecurityPolicy-TLS13-1-2-`/`-1-3-`; `drop_invalid_header_fields` non attivo; access log assenti; **deletion protection assente in prod** | redirect 301 a HTTPS, `ELBSecurityPolicy-TLS13-1-2-2021-06`, `drop_invalid_header_fields = true`, `access_logs { enabled = true … }`, `enable_deletion_protection = var.deletion_protection` |
| `sg-open` | block | ingress da `0.0.0.0/0` o `::/0` su porte diverse da 80/443; **sempre** su 22, 3389 e porte di database (3306, 5432, 1433, 6379, 27017); `dynamic "ingress"` non risolvibile con CIDR presi dall'iteratore. Le `var.*` si risolvono con default o `tfvars` della stessa cartella | security group sorgenti, prefix list o CIDR interni; accesso amministrativo con SSM Session Manager; regole in un `local` con valori letterali |
| `iam-least-privilege` | block | statement Allow con `Action "*"` (o `NotAction`) su `Resource "*"`; `iam:PassRole` su `*`; `Principal "*"` senza condizione che limiti chi accede; `AdministratorAccess`/`PowerUserAccess`; policy non leggibili (`file()`, `templatefile()`) | elenca azioni e ARN necessari; policy con `jsonencode({…})` o `data "aws_iam_policy_document"`; condizioni su `aws:SourceArn`, `aws:SourceAccount`, `aws:PrincipalOrgID` (`aws:SecureTransport` da solo non basta) |
| `kms-rotation` | block | chiave KMS senza `enable_key_rotation = true` | attivala |
| `logs-retention` | block | log group senza `retention_in_days` (0 non vale) e, **in prod**, senza `kms_key_id` | `retention_in_days = 90`; `kms_key_id = var.kms_key_arn` con la chiave nei `tfvars` di prod |
| `eks-hardening` | block | endpoint pubblico senza CIDR espliciti (o `0.0.0.0/0`); cluster senza `encryption_config` dei Secret; log del control plane incompleti (mancano `api`, `audit` o `authenticator`); node group senza launch template; launch template senza `http_tokens = "required"` | `endpoint_public_access = false` o `public_access_cidrs` espliciti, KMS per i Secret, tutti i tipi di log (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`), IMDSv2 obbligatorio |
| `ecr-hardening` | block | `image_tag_mutability` diverso da `IMMUTABLE`; scansione al push disattiva (senza enhanced scanning); repository senza lifecycle policy | `IMMUTABLE`, `scan_on_push = true`, `aws_ecr_lifecycle_policy` |
| `api-hardening` | block | route/metodo senza authorizer (`NONE`) salvo `public_routes` in config; stage senza access log; stage senza throttling | authorizer JWT/Cognito/Lambda/IAM; `access_log_settings` JSON con `correlationId`; `aws_api_gateway_method_settings` con throttling (o usage plan); la route davvero pubblica la aggiunge l'utente a `public_routes` |
| `lambda-hardening` | block | variabili d'ambiente con nome sensibile (`PASSWORD`, `SECRET`, `TOKEN`) e valore letterale; funzione senza tracing X-Ray; senza log group con retention | l'ARN del segreto (`DB_SECRET_ARN = aws_secretsmanager_secret.x.arn`), `tracing_config { mode = "Active" }`, `aws_cloudwatch_log_group` con retention |
| `api-coverage` | block | solo nei repository kybes (sezione `kybes` in config): operazione OpenAPI senza handler nella mappatura generata, handler inesistente in `services/`, function/microservizio/job senza infrastruttura, route o handler residui, `x-kybes-handler` incoerente con la mappatura, `handlers.auto.tfvars`/`jobs.auto.tfvars` mancanti o non leggibili | rigenera con `/kynfra:create-backend-infra-aws`; mai a mano i file `*.auto.tfvars` |

Gli attributi di sicurezza si verificano sul **letterale**: un valore che dipende da un'espressione non verificabile (variabile, funzione) è trattato come non conforme, salvo dove la regola prevede il valore per ambiente (toggle di prod, retention, ARN). I riferimenti `local.<nome>` dello stesso file si risolvono. Le espressioni dei toggle di prod nei moduli ammettono solo forme verificabili: `var.<ammessa>`, `var.<ammessa> ? <riferimento> : null`, un riferimento a risorsa, il letterale `true`.

### Toggle di prod

Alcune protezioni sono per ambiente (WAF di CloudFront, deletion protection del load balancer, KMS sui log group). Nei moduli non si conosce l'ambiente: l'attributo deve dipendere da una variabile ammessa (`waf_enabled`, `deletion_protection`, `kms_key_arn`, …) e il controllo d'insieme `prod_toggles` verifica che **ogni stack di prod** che usa il modulo la attivi (argomento, `terraform.tfvars`, `*.auto.tfvars` o default). Le violazioni sono riportate dalle regole `cloudfront-https`, `lb-https` e `logs-retention`.

## Comandi shell (`bash_guard.py`)

Il guard scompone il comando come farebbe la shell (virgolette, escape, `;`/`&&`/`||`/`|`/a capo, `$(…)` e backtick, heredoc, variabili assegnate nel comando, alias, funzioni) e analizza ricorsivamente i comandi che ne lanciano altri (`env`, `sudo`, `xargs`, `bash -c`, `eval`, `docker run`, `ssh`…). Le ricette di `make`/`npm run`/`just`/`task` e gli script del repository lanciati dall'agente sono letti e controllati con le stesse regole. Rifiuta:

| Categoria | Rifiutato | Consentito |
|---|---|---|
| Terraform / OpenTofu | `apply`, `destroy`, `import`, `taint`, `untaint`, `state` mutante, `force-unlock`, `workspace new\|delete`, `init` con backend reale, **`plan`** (richiede credenziali: lo lancia il DevOps), ogni assegnazione `TF_CLI_ARGS*`; anche con alias e percorsi (`tf`, `tofu`, `terragrunt`, `.kynfra/bin/terraform`) | `fmt`, `validate`, `version`, `providers`, `graph`, `show`, `output -json`, `state list\|show`, `workspace list\|show\|select`, `init -backend=false` |
| CLI cloud | `aws` mutante, `kubectl` mutante, `helm` mutante, `az`, `gcloud`, `vercel`, `pulumi`, `cdk` e simili; il codice inline che usa gli SDK cloud; `aws secretsmanager get-secret-value` e `aws ssm get-parameter*` con `--with-decryption` (un segreto non deve entrare nella conversazione) | `aws` con `get-*`, `describe-*`, `list-*`, `s3 ls`, `s3api head-*`; `kubectl get\|describe\|explain\|version\|config view\|get-contexts`; `helm template\|lint\|show\|version\|list\|status`; `az`/`gcloud` solo `--version`/`help` |
| Download di strumenti | `curl \| sh`, `curl -o`, `wget`, gestori di pacchetti (`brew`, `apt`, `pip install`, `npm i -g`, `go install`, `tfenv`…) | `tools.py install <strumento>` (vedi [strumenti](strumenti.md)) |
| Scritture da shell | file IaC sotto `infra_root`, `.env*`, hook e config di git, file protetti (`>`, `tee`, `sed -i`, `cp`/`mv`, `curl -o`, script inline), `git apply`/`patch`, `install.sh --force/--uninstall`, variabili d'ambiente che fanno eseguire codice (`LD_PRELOAD`, `GIT_SSH_COMMAND`, `PYTHONPATH`, `BASH_ENV`…) | `generate.py`, `arch_check.py`, `tools.py`, `stop_gate.py` del kit |

Il codice si scrive con gli strumenti di modifica dei file, non da shell, così le regole valutano il risultato.

### Un controllo euristico

`bash_guard` è **euristico**: ciò che non si può determinare (comando in una variabile ignota, script da pipe, percorso di scrittura calcolato) viene rifiutato, e un comando non riconosciuto con file IaC come argomento è trattato con cautela; ma nessun analizzatore di shell è una prova. **La barriera decisiva contro un `apply` dell'agente è che la sessione dell'agente non ha credenziali cloud**: senza credenziali nessun comando può toccare un account, qualunque sia il modo in cui è scritto. Il guard riduce il rischio e rende espliciti i tentativi; lo stop gate e la CI sono le barriere dietro. Tieni le credenziali (profili AWS SSO, variabili `AWS_*`) fuori dall'ambiente in cui lavora l'agente.

## Stop gate

`stop_gate.py` impedisce di chiudere il lavoro finché i controlli non passano. Gira alla chiusura dell'agente principale (`Stop`) e di ogni subagente (`SubagentStop`, solo Claude Code) ed esegue, nell'ordine:

1. `arch_check` (regole di kynfra su tutto `infra_root`, compreso `api-coverage` e la soglia di `literal-reuse`);
2. `terraform fmt -check -recursive` (o `tofu`);
3. per ogni stack (`envs/<env>/<stack>/`, `envs/shared/<stack>/`, `bootstrap/`): `init -backend=false` e `validate`, con una `TF_DATA_DIR` temporanea (nessun `.terraform` lasciato nel progetto);
4. `tflint --recursive` con `.tflint.hcl` (ruleset AWS dalla versione di `versions.json`);
5. lo scanner: Checkov (default, con la baseline del kit) o Trivy `config`;
6. i comandi di `stop_gate.commands`.

Comportamento:

- **Strumento mancante**: in locale è un **avviso** con il comando per installarlo (`/kynfra:tools`), non un blocco (le regole interne bloccano comunque); in CI (`--strict`) è un errore.
- **Anti-loop**: blocca fino a `max_blocks` volte di fila nella stessa catena di stop, poi lascia chiudere con l'avviso esplicito "NON è conforme". `stop_hook_active` non sblocca il gate: serve solo a capire se la catena è nuova.
- **`only_if_changes`**: "ci sono modifiche" non è solo `git status`; conta anche `HEAD` diverso da quello di inizio sessione e i commit non ancora pubblicati, quindi **un commit non spegne il gate**.
- **Monorepo**: se il cwd non è un progetto kynfra, controlla i progetti kynfra sotto il cwd.

### Fail closed

Un guardrail che si rompe non deve lasciar passare in silenzio. Per questo: un file che il parser non legge è un blocco (`hcl-syntax`); una regola che solleva un'eccezione produce un blocco `errore interno della regola`; `pre_write` che fallisce su un file soggetto alle regole nega la scrittura; lo stop gate che incontra un errore inatteso blocca come un controllo fallito (con lo stesso anti-loop, quindi al massimo `max_blocks` volte), e se il contatore non è scrivibile blocca una volta sola per catena. Un bug di kynfra può quindi fermare il lavoro finché non è corretto, ma non lo fa passare non verificato.

## CI

Il workflow `kynfra-check.yml` (copiato dall'installer con `--ci github`) installa gli strumenti del registro con `tools.py install <strumento> --approved-by ci`, uno step per strumento, e lancia `arch_check.py . --strict --external`: gli avvisi diventano errori e uno strumento mancante fallisce la build. Non ha credenziali né permessi oltre `contents: read`. La CI del kit stesso è descritta in [sviluppo](sviluppo.md).
