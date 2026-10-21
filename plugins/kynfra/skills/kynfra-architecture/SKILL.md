---
name: kynfra-architecture
description: Binding rules for designing, planning and writing Terraform infrastructure on AWS (folder layout, remote state, version pinning, tags, accounts, secrets, S3/CloudFront/ALB/EKS/ECR/API/Lambda hardening, exceptions, shell limits). Use before any plan or change to infrastructure code in a project that has .kynfra/config.json.
---

# kynfra — Know Your Infrastructure

Queste regole sono vincolanti per ogni piano e ogni riga di infrastruttura. Se una richiesta le viola, dichiaralo e proponi l'alternativa conforme prima di scrivere codice.

La configurazione è in `.kynfra/config.json` (`infra_root`, `project`, `iac`, `region`, ambienti, account, tag, regole, eccezioni, comandi dello stop gate). Leggila all'inizio del lavoro: i valori lì prevalgono sugli esempi. Il file lo modifica solo l'utente, come `tools/kynfra/`, `.terraform.lock.hcl`, le impostazioni e gli hook dell'agente (`.claude/settings*.json`, `.codex/hooks.json`, `.codex/config.toml`) e i file di kynfra in `.claude/rules/`, `.agents/skills/`, `.codex/agents/` e `.github/workflows/`: gli hook rifiutano ogni modifica (`protected-files`), anche via shell. Il codice si scrive con gli strumenti di modifica dei file (Write/Edit, `apply_patch`), non con redirect, `sed -i`, `cp`/`mv` o `git apply` da shell, così le regole valutano il risultato.

Le API di Terraform e del provider AWS cambiano: prima di usare un argomento di cui non sei certo consulta la documentazione aggiornata (Context7 o registry Terraform) per la versione del provider bloccata nel progetto. Le regole qui sotto non cambiano con la versione.

Nomi esatti di risorse e argomenti per pattern: `references/aws.md`.

## 1. Alberatura (sotto `infra_root`)

`infra_root` è `infra` se nel repository ci sono `.kybes/`, `.kyfes/` o `infra/`, altrimenti `.`. Le regole si applicano solo ai file sotto `infra_root`.

```text
bootstrap/                      stato remoto: bucket S3 (versioning, KMS, public access block, TLS only); unico posto con backend locale
modules/<pattern>/              modulo riutilizzabile: main.tf, variables.tf, outputs.tf, versions.tf, README.md
envs/<env>/<stack>/             root module: backend.tf, providers.tf, versions.tf, main.tf, variables.tf, terraform.tfvars, outputs.tf, .terraform.lock.hcl
envs/shared/<stack>/            risorse condivise tra ambienti (hosted zone, ECR)
native/<pattern>/               solo se Terraform non copre (sez. 6)
```

- Pattern: `network`, `spa`, `backend`, `elb`, `eks`, `ecr`, `secrets`. Comandi: `/kynfra:create-<pattern>-infra-aws`.
- Ambienti di default `dev`, `staging`, `prod`, regione `eu-south-1`; gli ambienti ammessi sono quelli in config.
- **Uno stack per pattern e ambiente**, ciascuno con il suo stato. Gli stack leggono gli output degli altri con `terraform_remote_state` sullo stesso backend (es. `eks` legge le subnet di `network`).
- **Differenze tra ambienti solo nei `tfvars`**: stesso modulo, valori diversi. `prod` è più restrittivo (sez. 4.6).
- Moduli **solo con risorse native dei provider**: nessun modulo di terze parti (`terraform-aws-modules` e simili). Moduli locali `../../modules/...`.
- Nomi delle risorse prefissati `<progetto>-<env>`: nello stesso account convivono tutti gli ambienti.
- Dopo la generazione `modules/` ed `envs/` sono codice del progetto: li puoi modificare, sempre passando dalle regole.

## 2. Regole (default `block` salvo `warn` indicato)

Ogni scrittura è valutata sul file risultante; lo stop gate e la CI controllano tutto il progetto. La severità si cambia solo in config (`rules: {"<regola>": "warn"}`).

### 2.1 Trasversali

| Regola | Cosa rifiuta |
|---|---|
| `protected-files` | modifiche ai file protetti (config, kit, impostazioni e hook dell'agente, regole/skill/agenti di kynfra, workflow CI di kynfra, `.terraform.lock.hcl`) |
| `config` (warn) | `.kynfra/config.json` incompleta o incoerente: segnala campi mancanti, ambienti senza account, tag vuoti |
| `folder-layout` | file IaC fuori da `bootstrap/`, `modules/`, `envs/<env>/<stack>/`, `envs/shared/<stack>/`, `native/`; ambienti non in config; nomi non kebab-case |
| `hcl-syntax` | file `.tf`, `.tfvars`, `.tf.json` che non si possono leggere (parentesi, stringhe o heredoc non chiusi) |
| `remote-state` | root module senza backend `s3` con `encrypt = true` e `use_lockfile = true` (letterali); backend locale fuori da `bootstrap/` |
| `version-pinning` | `required_version` o `required_providers` senza vincolo pessimistico `~>`; moduli esterni senza versione o ref fissa (git con `?ref=` di un tag o commit) |
| `static-credentials` | `access_key`, `secret_key`, token nei provider, nei `tfvars` o nelle variabili con default: usa profilo, SSO o OIDC |
| `secrets` | segreti in chiaro (chiavi, password, connection string) in `.tf`, `.tfvars`, `native/`; `secret_string` con letterale; variabili riservate senza `sensitive = true` o con default |
| `required-tags` | provider `aws` senza `default_tags` con `Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy = "kynfra"`: le **chiavi** devono essere letterali |
| `account-guard` | provider `aws` negli stack senza `allowed_account_ids` |
| `scanner-suppression` | commenti `checkov:skip`, `trivy:ignore`, `tflint-ignore` |
| `no-provisioners` | `local-exec`, `remote-exec` e simili: comandi fuori dal controllo di Terraform |
| `native-params` | template in `native/` con parametri senza `Type`, riservati con default o senza `NoEcho: true` |
| `api-coverage` | (solo repo kybes) operazione di `openapi.yaml` senza handler, o function/microservizio/job senza infrastruttura |
| `variables-typed` (warn) | variabili senza `type` o `description` |
| `region-pinning` (warn) | regione o account ID scritti come letterali nei moduli: vanno in variabili/`tfvars` |
| `literal-reuse` (warn) | stesso letterale di dominio (CIDR, domini, nomi, porte) ripetuto in più file invece di `locals`/variabili; allo stop gate blocca oltre la soglia in config |

### 2.2 AWS

| Regola | Cosa rifiuta |
|---|---|
| `s3-private` | bucket senza `aws_s3_bucket_public_access_block` con i 4 flag `true` (letterali), con ACL pubbliche o grant a `AllUsers`, senza cifratura, senza policy TLS only (`Deny` con `aws:SecureTransport = "false"`), senza versioning attivo |
| `cloudfront-https` | `viewer_protocol_policy = "allow-all"`, TLS minimo sotto `TLSv1.2_2021` o certificato di default, origin S3 con OAI (`s3_origin_config`) o endpoint website pubblico invece di OAC, senza response headers policy, senza log, senza WAF in prod |
| `lb-https` | listener HTTP che non fa redirect a HTTPS, listener HTTPS senza policy TLS moderna, `drop_invalid_header_fields` non attivo, access log assenti, deletion protection assente in prod |
| `sg-open` | ingress da `0.0.0.0/0` o `::/0` su porte diverse da 80/443 e, sempre, su 22, 3389 e porte di database; `dynamic "ingress"` con CIDR che non vengono da `locals` letterali |
| `iam-least-privilege` | `Action = "*"` con `Resource = "*"`, `AdministratorAccess`/`PowerUserAccess`, `iam:PassRole` su `*`, trust policy con principal `*` senza condizioni; policy non verificabili |
| `kms-rotation` | chiavi KMS senza `enable_key_rotation = true` |
| `logs-retention` | log group senza `retention_in_days` (e senza KMS in prod) |
| `eks-hardening` | endpoint pubblico senza CIDR espliciti, senza cifratura dei Secret con KMS, senza log del control plane, node group senza launch template con IMDSv2 obbligatorio |
| `ecr-hardening` | tag mutabili, scansione al push disattiva, repository senza lifecycle policy |
| `api-hardening` | route senza authorizer (salvo `public_routes` in config), stage senza throttling o senza access log |
| `lambda-hardening` | variabili d'ambiente con nomi sensibili e valori letterali, funzioni senza tracing X-Ray o senza log group con retention |

## 3. Come si scrive il codice perché le regole lo capiscano

Le regole leggono il testo HCL, non eseguono Terraform: ciò che non riescono a verificare viene rifiutato. Quindi:

- **Tag**: le chiavi richieste (`Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy`) sono letterali in `default_tags`; solo i valori possono essere espressioni. `ManagedBy = "kynfra"`.
- **Attributi di sicurezza letterali**: i 4 flag del public access block, `viewer_protocol_policy`, `minimum_protocol_version`, `ssl_policy`, `drop_invalid_header_fields`, `enable_key_rotation`, `image_tag_mutability`, `http_tokens`, `encrypt`, `use_lockfile` hanno valori scritti, non `var.*` o espressioni.
- **Policy IAM** solo con `jsonencode({...})`, heredoc o `data "aws_iam_policy_document"`. Mai `file()` o `templatefile()`: il documento non sarebbe verificabile.
- **Ingress dinamico**: se serve `dynamic "ingress"`, `for_each = local.<nome>` con CIDR e porte letterali in un `locals`. Altrimenti blocchi o risorse espliciti.
- **Toggle di prod** (WAF, deletion protection, KMS dei log): nel modulo `var.<nome ammesso>`, `var.<nome> ? <riferimento> : null`, un riferimento semplice o `true`; si attivano nei `tfvars` di `envs/prod/<stack>/`. Nomi ammessi: WAF `waf_enabled`/`web_acl_arn`/`web_acl_id`; deletion protection `deletion_protection`/`enable_deletion_protection`; KMS dei log `kms_key_arn`/`kms_key_id`/`logs_kms_key_arn`. Nessun'altra espressione.
- **Nessuna soppressione inline** (`checkov:skip`, `trivy:ignore`, `tflint-ignore`).
- **Valori non ripetuti**: nomi, CIDR, porte, domini e tag vivono in `locals` o variabili, non come letterali ripetuti tra file (`literal-reuse`).
- **Variabili** sempre con `type` e `description`; `sensitive = true` per ciò che è riservato; `validation` dove il dominio è chiuso (ambienti, regioni, CIDR).

## 4. Principi

### 4.1 Stato remoto
Backend S3 con `encrypt = true` e `use_lockfile = true` (lock nativo, senza DynamoDB), chiave `<progetto>/<env>/<stack>.tfstate`. Un solo `bootstrap/` per account crea il bucket dello stato.

### 4.2 Versioni
`required_version` e `required_providers` (`aws`, `helm`, `random`) con `~>`; `.terraform.lock.hcl` committato (lo rigenera solo `terraform init`, eseguito dallo stop gate o dall'utente). Le versioni stanno in `templates/versions.json` e non si inventano.

### 4.3 Provider AWS
`default_tags` con i cinque tag e `allowed_account_ids = [var.account_id]`, così un `apply` sull'account sbagliato fallisce. Nessuna credenziale nel provider: profilo, SSO o OIDC. Per CloudFront serve un secondo provider con `alias = "us_east_1"` per il certificato ACM, con gli stessi `default_tags` e `allowed_account_ids`.

### 4.4 Account (sez. 5.2 della spec)
v1: un solo account per tutti gli ambienti, ma descritto in config (`accounts`, `environments.<env>.account`). Ogni stack riceve `account_id` dai `tfvars` e lo usa in `allowed_account_ids`. Niente ID di account o regioni scritti nei moduli (`region-pinning`). Le risorse condivise tra ambienti (hosted zone, ECR) stanno in `envs/shared/`. Il passaggio a più account (`/kynfra:manage-accounts-aws`) è una fase successiva: il codice non deve dare per scontato l'account unico.

### 4.5 Segreti (sez. 5.3 della spec)
Nessun valore di segreto nei file, nelle variabili, nei `tfvars` o nello stato. I segreti si creano come contenitori (`aws_secretsmanager_secret`); il valore lo inserisce il DevOps fuori da Terraform, o lo genera AWS (`manage_master_user_password` per RDS, rotazione con Lambda). Dove un valore deve passare da Terraform, argomenti write-only (`*_wo`) se il provider li supporta, da una `variable` con `sensitive = true` e senza default. Le app leggono i segreti a runtime con il proprio ruolo IAM. **L'agente non legge mai segreti**: `aws secretsmanager get-secret-value`, `ssm get-parameter --with-decryption` e simili sono rifiutati dalla shell.

### 4.6 Ambienti e prod
`prod` è più restrittivo per default: deletion protection, NAT per AZ, WAF attivo, KMS e retention più lunga sui log, backup. Si ottiene con variabili nei `tfvars`, non con moduli diversi.

## 5. Eccezioni (sez. 7.4 della spec)

Nessuna soppressione inline. Un'eccezione è una voce in `.kynfra/config.json`: `exceptions: [{rule, path, resource, reason, expires}]`, con motivo e scadenza obbligatori; la scrive solo l'utente (file protetto). Scaduta `expires`, la regola torna a bloccare. Se una regola ti ostacola, correggi la causa; se serve davvero un'eccezione, chiedila all'utente indicando regola, percorso, risorsa e motivo.

Per lo scanner (Checkov o Trivy) il kit ha una baseline di controlli esclusi, motivati e limitati per ambiente e percorso (es. solo `bootstrap/**`), in `tools/kynfra/` (protetta): vale solo per quei file, il resto dei controlli falliti blocca.

## 6. Dove Terraform non copre (sez. 5.4 della spec)

Ordine di preferenza: (1) provider Terraform ufficiale; (2) provider ufficiale "a basso livello" (`awscc`); (3) template nativo CloudFormation in `native/<pattern>/`, **orchestrato da Terraform** (`aws_cloudformation_stack`) così stato, tag e controlli restano unici; (4) file di configurazione nativi della piattaforma. I file in `native/` non contengono segreti e hanno parametri tipizzati (`native-params`).

## 7. Shell: cosa l'agente non esegue (sez. 7.5 della spec)

Gli hook rifiutano, e tu non tenti:
- `terraform`/`tofu` `apply`, `destroy`, `import`, `taint`, `untaint`, `plan`, `force-unlock`, `state` mutante, `workspace new|delete`, `init` senza `-backend=false`. Consentiti: `fmt`, `validate`, `init -backend=false`, `state list|show`, `version`.
- CLI cloud mutanti: `aws` (solo `get-*`, `describe-*`, `list-*`, `sts get-caller-identity`; mai la lettura di segreti), `az`, `gcloud`, `vercel`, `kubectl` (solo `get`, `describe`, `explain`), `helm` (solo `template`, `lint`, `show`).
- Download e installazione di strumenti fuori da `tools.py` (`curl | sh`, `brew install`, `pip install`, `npm i -g`).
- Scritture di file IaC da shell, modifiche ai file protetti, `git apply`, `install.sh --force` e `--uninstall`.

`plan` e `apply` li esegue il DevOps, con le sue credenziali. Gli strumenti esterni (Terraform, TFLint, ruleset AWS, Checkov o Trivy) si installano solo con la skill `kynfra-tools`, uno strumento alla volta e con l'approvazione dell'utente.

## 8. Controlli prima di chiudere

Lo stop gate non ti lascia chiudere finché non passano; eseguili tu prima:
1. `python3 -B tools/kynfra/plugins/kynfra/scripts/arch_check.py . --strict --external` (regole di kynfra su tutto `infra_root` e strumenti esterni);
2. `terraform fmt -check -recursive` (o `tofu`);
3. per ogni stack `terraform init -backend=false` e `terraform validate`;
4. `tflint --recursive` con il ruleset AWS;
5. lo scanner configurato (`checkov` o `trivy config`).

Se uno strumento esterno non è installato, segnalalo all'utente e proponi `/kynfra:kynfra-tools`: non bloccare su di esso, ma le regole interne bloccano comunque. In CI tutti gli strumenti sono obbligatori.

## 9. Checklist di consegna

- [ ] File solo nell'alberatura ammessa; uno stack per pattern e ambiente; nomi `<progetto>-<env>`.
- [ ] Backend S3 con `encrypt` e `use_lockfile`; chiave `<progetto>/<env>/<stack>.tfstate`; versioni con `~>`.
- [ ] Provider con i cinque tag letterali e `allowed_account_ids`; nessuna credenziale statica.
- [ ] Nessun segreto in chiaro; variabili riservate `sensitive`; segreti solo come contenitori.
- [ ] Regole AWS del pattern rispettate (sez. 2.2) con valori letterali dove richiesto.
- [ ] Differenze tra ambienti solo nei `tfvars`; toggle di prod attivi in `envs/prod`.
- [ ] Nessuna soppressione inline; eccezioni solo in config, con motivo e scadenza.
- [ ] Valori ripetuti in `locals`/variabili; variabili con `type` e `description`.
- [ ] `arch_check --strict --external`, fmt, validate, tflint e scanner senza errori.
- [ ] Riportati all'utente: file creati, comandi da eseguire (`init`, `plan`, `apply`), cosa resta manuale (delega NS, valori dei segreti).

## 10. Formato obbligatorio del piano

Ogni piano contiene, in quest'ordine:

1. Tabella `Risorsa | Pattern/modulo | Stack | Ambienti | Differenze tra ambienti | Controlli di sicurezza | Dipendenze (remote state)`.
2. Variabili e output nuovi (con `type`, `description`, `sensitive`).
3. Segreti coinvolti e come arriva il valore (inserito dal DevOps fuori da Terraform, generato da AWS, write-only).
4. Impatto sui costi: risorse a costo fisso (NAT, EKS, ALB, WAF, endpoint VPC) per ambiente.
5. Comandi che il DevOps dovrà eseguire (`init`, `plan`, `apply`) e passaggi manuali.
6. Violazioni richieste e alternative conformi.
7. Task piccoli e indipendenti, ciascuno con i file coinvolti.
