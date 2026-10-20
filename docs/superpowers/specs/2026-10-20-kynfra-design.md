# kynfra — Know Your Infrastructure: design

Data: 2026-10-20 · Stato: approvato

## 1. Intento

kynfra è il terzo membro della famiglia di plugin per Claude Code e Codex, accanto a **kybes** (backend) e
**kyfes** (frontend). Serve ai **DevOps**: genera ambienti infrastrutturali completi, **guidati e protetti da
guardrail**, con le best practice di ogni piattaforma già applicate. Il DevOps descrive cosa vuole ospitare e kynfra
produce tutta la configurazione Infrastructure as Code, validata, pronta per essere applicata dal DevOps.

Esempio dell'utente: `/kynfra:create-spa-infra-aws` crea tutto il necessario su AWS per ospitare una SPA (bucket S3,
CloudFront, Route53, certificato e HTTPS, routing, API Gateway eventuale).

Come kyfes, le regole che si possono verificare automaticamente **non sono consigli nel prompt**: le applicano hook,
stop gate e CI.

## 2. Obiettivi, non obiettivi, anti-obiettivi

**Obiettivi (v1)**
- Plugin installabile per Claude Code e Codex, con la stessa architettura di kyfes (sez. 4).
- Sette pattern AWS generabili con un comando ciascuno (sez. 6): rete, frontend SPA, backend, load balancer,
  Kubernetes (EKS), registry di container (ECR), segreti (Secrets Manager).
- Ambienti multipli (`dev`, `staging`, `prod` di default) dallo stesso codice, con differenze solo nelle variabili.
- Ogni file scritto dall'agente passa dalle regole; il lavoro non si chiude finché `fmt`, `validate`, lint, scanner di
  sicurezza e controlli di kynfra non passano.
- Funziona sia dentro un repository applicativo kybes/kyfes (cartella `/infra`) sia in un repository di sola
  infrastruttura.
- Motore e regole progettati per accogliere Azure, Vercel e altre piattaforme senza riscrivere nulla.

**Non obiettivi (v1)**
- Pipeline CI/CD di `plan`/`apply` e approvazioni: fase successiva (roadmap).
- Azure, Vercel, GCP, Cloudflare: fasi successive.
- Gestione dei workload Kubernetes (manifest applicativi, Helm chart delle app): è compito di kybes.
- Più account AWS: per ora un account unico; il gestore degli account è una fase successiva (sez. 5.2).

**Anti-obiettivi (sarebbe un fallimento anche se "funziona")**
- kynfra o l'agente **toccano un account cloud**: nessun `apply`, `destroy`, `import`, `state` mutante, né comandi
  mutanti delle CLI (`aws`, `az`, `kubectl`, `helm`, `vercel`). Solo generazione e validazione locale.
- Segreti in chiaro nei file, nelle variabili, nei `tfvars` o nello stato.
- Ambienti diversi da generazione a generazione per la stessa richiesta (varianza architetturale, il problema che
  kyfes risolve per il frontend).
- Guardrail aggirabili dall'agente (soppressioni inline, modifica della config, scritture da shell).

## 3. Decisioni prese con l'utente

| Tema | Decisione |
|---|---|
| Linguaggio IaC | **Terraform** come linguaggio principale e trasversale. Dove Terraform non copre: linguaggio nativo della piattaforma o un equivalente compatibile |
| Perimetro | Fino ai **file di configurazione validati**. Le pipeline arrivano dopo |
| Prima piattaforma | **AWS** |
| Pattern v1 | backend, ELB, Kubernetes, frontend, **ECR**, **secret vault** (+ rete di base, aggiunta come prerequisito) |
| Contesto d'uso | **Entrambi**: dentro i repo kybes/kyfes e in repo di sola infrastruttura |
| Comandi | uno per pattern e piattaforma, sul modello di `/kynfra:create_spa_infra_aws` |
| Account AWS | **un account unico** per ora; previsto un **gestore degli account** per passare a più account (sez. 5.2) |
| Backend | il comando backend **legge il progetto kybes e crea l'infrastruttura completa** di ogni function, microservizio e job (sez. 6.2) |

## 4. Architettura del plugin (ricalca kyfes)

```text
kynfra/
├── .claude-plugin/marketplace.json          marketplace Claude Code
├── .agents/plugins/marketplace.json         marketplace Codex
├── install.sh                               wrapper → plugins/kynfra/install.sh
├── README.md                                in inglese, con banner (come kyfes)
├── docs/                                    documentazione in italiano
├── tests/{run.sh,hooks/,patterns/}          test del kit
├── .github/workflows/kit-tests.yml          CI del kit
└── plugins/kynfra/
    ├── .claude-plugin/plugin.json
    ├── .codex-plugin/plugin.json
    ├── install.sh                           installer idempotente (stesse opzioni di kyfes, sez. 4.3)
    ├── hooks/hooks.json                     SessionStart, PreToolUse (scritture + shell), PostToolUse, Stop, SubagentStop
    ├── agents/{architect,implementer,reviewer}.md
    ├── scripts/                             solo libreria standard Python 3
    │   ├── hcl.py                           tokenizer/parser HCL minimale (blocchi, attributi, liste, oggetti, espressioni come testo)
    │   ├── rules.py                         motore delle regole (sez. 7)
    │   ├── rules_aws.py                     regole specifiche AWS (una per famiglia di risorse)
    │   ├── hook_common.py, pre_write.py, post_edit.py, bash_guard.py, session_start.py, stop_gate.py, arch_check.py
    │   └── generate.py                      generatore deterministico dei pattern (sez. 6.3)
    ├── skills/
    │   ├── kynfra-architecture/SKILL.md     regole vincolanti + references/aws.md (poi azure.md, vercel.md…)
    │   ├── kynfra-init/  kynfra-plan/  kynfra-review/
    │   └── create-<pattern>-infra-aws/      un comando per pattern (sez. 6)
    └── templates/
        ├── kynfra.config.json, AGENTS.kynfra.md, rules/*.md, codex-agents/*.toml, codex-hooks.json, ci/kynfra-check.yml
        └── aws/
            ├── modules/<pattern>/           moduli Terraform di riferimento
            ├── stacks/<pattern>/            root module per ambiente che richiama il modulo
            └── bootstrap/                   bucket dello stato remoto
```

### 4.1 Comportamento identico a kyfes
- Senza `.kynfra/config.json` ogni hook è un no-op.
- Il progetto si individua dal file scritto (config più vicina), quindi funziona anche nei monorepo.
- `pre_write` valuta il **file risultante** e blocca solo ciò che la modifica introduce; lo stop gate e la CI
  controllano tutto.
- Stop gate con anti-loop (`max_blocks`), baseline di `HEAD` a inizio sessione, `only_if_changes`.
- File protetti: `.kynfra/`, `tools/kynfra/`, impostazioni e hook dell'agente, regole/skill/agenti di kynfra,
  workflow CI di kynfra, `.terraform.lock.hcl` (lo rigenera solo `terraform init`, eseguito dallo stop gate o dall'utente).
- Regole `permissions.deny` in `.claude/settings.json` come seconda barriera.
- Kit versionato copiato in `tools/kynfra/` per CI, colleghi e hook di Codex.
- Blocco gestito `<!-- kynfra:start … kynfra:end -->` in `CLAUDE.md` e `AGENTS.md`.

### 4.2 Adattamento al contesto (repo applicativo o di sola infrastruttura)
L'installer rileva `.kybes/` o `.kyfes/` (o una cartella `infra/` già presente): in quel caso `infra_root = "infra"`,
altrimenti `infra_root = "."`. Il valore resta modificabile in config. Le regole di kynfra si applicano solo ai file
sotto `infra_root`, così convivono con quelle di kybes/kyfes nello stesso repository senza sovrapporsi.

### 4.3 Installer
`install.sh [--target DIR] [--iac terraform|opentofu] [--providers aws] [--infra-root DIR] [--envs dev,staging,prod]
[--region eu-south-1] [--agents claude|codex|both] [--ci github|none] [--scope local|project|user] [--no-plugin]
[--force] [--uninstall]` — idempotente, non sovrascrive config e file esistenti salvo `--force`; `--force` e
`--uninstall` li esegue solo l'utente (rifiutati da `bash_guard`).

## 5. Struttura del codice generato

Sotto `infra_root`:

```text
bootstrap/                      stato remoto: bucket S3 (versioning, cifratura KMS, public access block, TLS only)
modules/<pattern>/              modulo riutilizzabile: main.tf, variables.tf, outputs.tf, versions.tf, README.md
envs/<env>/<stack>/             root module: backend.tf, providers.tf, versions.tf, main.tf, variables.tf,
                                terraform.tfvars, outputs.tf, .terraform.lock.hcl
native/<pattern>/               solo se serve (sez. 5.4)
```

### 5.1 Principi
- **Uno stack per pattern e ambiente**, ognuno con il suo stato: blast radius ridotto, `apply` indipendenti. Gli stack
  leggono gli output degli altri con `terraform_remote_state` sullo stesso backend (es. `kubernetes` legge le subnet
  di `network`).
- **Stato remoto con lock** fin dal primo giorno: backend S3 con `encrypt = true` e `use_lockfile = true` (lock nativo,
  senza DynamoDB); la chiave segue `<progetto>/<env>/<stack>.tfstate`. Mai backend locale fuori da `bootstrap/`.
- **Versioni bloccate**: `required_version` e `required_providers` con vincolo pessimistico (`~>`), lock file committato.
  Moduli solo locali (`../../modules/...`) o, se esterni, con versione/ref fissata.
- **Provider AWS** con `default_tags` (tag obbligatori: `Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy =
  kynfra`) e `allowed_account_ids` per ambiente, così un `apply` sull'account sbagliato fallisce. Nessuna credenziale
  nel provider: profilo, SSO o OIDC.
- **Differenze tra ambienti solo nei `tfvars`**: stesso modulo, valori diversi. `prod` è più restrittivo per default
  (deletion protection, NAT per AZ, WAF attivo, retention log più lunga, backup).
- **Valori non ripetuti** (l'equivalente di `constants.ts` di kyfes): nomi, CIDR, porte, domini e tag vivono in
  `locals` o variabili, non come letterali ripetuti tra file.
- **Variabili** sempre con `type` e `description`; `sensitive = true` per tutto ciò che è riservato; `validation` dove
  il dominio è chiuso (ambienti, regioni, CIDR).
- **OpenTofu** supportato con gli stessi file (`--iac opentofu` cambia solo i comandi dello stop gate).

### 5.2 Account e gestore degli account
v1: un solo account AWS per tutti gli ambienti. La config descrive comunque gli account in modo esplicito, così il
passaggio a più account non cambia la struttura:

```json
"accounts": { "main": { "id": "123456789012" } },
"environments": { "dev": { "account": "main" }, "staging": { "account": "main" }, "prod": { "account": "main" } }
```

- Ogni stack riceve `account_id` dai `tfvars` dell'ambiente e lo usa in `allowed_account_ids`; un solo `bootstrap/`
  (bucket di stato) per account. Le risorse condivise tra ambienti (hosted zone, ECR) stanno in stack `envs/shared/`.
- Nomi delle risorse sempre prefissati da `<progetto>-<env>`, perché nello stesso account convivono tutti gli ambienti.
- **Gestore degli account (fase successiva)**: comando `/kynfra:manage-accounts-aws` che aggiunge account alla config,
  genera un `bootstrap/` per account, configura i provider con `assume_role` verso un ruolo per account, e rende
  cross-account le dipendenze (pull ECR, delega DNS, lettura dello stato). Il codice v1 non deve dare per scontato
  l'account unico: niente ID scritti nei moduli, `account_id` sempre passato.

### 5.3 Segreti
Nessun valore di segreto nei file. I segreti si creano come contenitori (`aws_secretsmanager_secret`) e il valore lo
inserisce il DevOps fuori da Terraform, oppure lo genera AWS (`manage_master_user_password` per RDS, rotazione con
Lambda). Dove un valore deve passare da Terraform si usano argomenti write-only (`*_wo`, non salvati nello stato) se il
provider li supporta. Le app leggono i segreti a runtime con il proprio ruolo IAM.

### 5.4 Dove Terraform non copre
Ordine di preferenza: (1) provider Terraform ufficiale; (2) provider ufficiale "a basso livello" della piattaforma
(es. `awscc` su AWS, `azapi` su Azure); (3) template nativo (CloudFormation, Bicep/ARM) in `native/<pattern>/`,
**orchestrato da Terraform** (`aws_cloudformation_stack`, `azapi`/deployment ARM) così stato, tag e controlli restano
unici; (4) file di configurazione nativi della piattaforma (es. `vercel.json`) quando la piattaforma configura solo
così. I file in `native/` hanno le loro regole (niente segreti, parametri tipizzati) e passano dallo scanner.

## 6. Pattern AWS della v1

Ogni pattern ha: una skill-comando `create-<pattern>-infra-aws`, un modulo in `templates/aws/modules/`, uno stack
per ambiente, regole dedicate e un test in CI.

| Comando | Cosa genera (best practice incluse) |
|---|---|
| `/kynfra:create-network-infra-aws` | VPC su 2–3 AZ, subnet pubbliche/private/isolate (dati), NAT (uno per AZ in prod, uno solo altrove), VPC endpoint (S3, ECR, Secrets Manager, STS, CloudWatch Logs), flow log su CloudWatch cifrati, default security group senza regole |
| `/kynfra:create-spa-infra-aws` | S3 privato (public access block, cifratura, versioning, TLS only), CloudFront con **OAC**, certificato ACM in `us-east-1` con validazione DNS, record Route53 alias A/AAAA, HTTPS obbligatorio (redirect) e TLS ≥ 1.2, fallback del routing client-side su `index.html` (CloudFront Function, non risposte d'errore 403/404 che mascherano le API), response headers policy (HSTS, CSP, X-Content-Type-Options, frame-ancestors), cache policy (asset immutabili a lungo, `index.html` no-cache), log di accesso, WAF (managed rule set) obbligatorio in prod, opzionale `/api/*` verso l'origin API Gateway sullo stesso dominio |
| `/kynfra:create-backend-infra-aws` | infrastruttura **completa** del backend kybes, letta dal progetto (sez. 6.2): API Gateway REST generato da `schemas/openapi.yaml` con validazione delle richieste, versioning `/v1`, authorizer JWT (OIDC), throttling, WAF, access log JSON con `correlationId`; una Lambda per function (timeout ≤ 10 s, ruolo IAM dedicato, X-Ray, log group con retention, accesso al DB tramite RDS Proxy, nessun segreto nelle variabili d'ambiente); VPC link verso i microservizi su EKS; code SQS con DLQ e ruoli Pod Identity per i job |
| `/kynfra:create-elb-infra-aws` | ALB (o NLB su richiesta) con listener HTTPS, policy TLS moderna, redirect 80 → 443, certificato ACM, `drop_invalid_header_fields`, access log su S3, WAF, deletion protection in prod, target group con health check, security group che accetta solo 443/80 dal mondo (o solo da CloudFront tramite prefix list) |
| `/kynfra:create-eks-infra-aws` | EKS (autoscaling dei nodi con **Karpenter**, come richiede kybes) con endpoint API privato (pubblico solo con CIDR espliciti), cifratura dei Secret con KMS, log del control plane, access entries (non `aws-auth`), node group gestiti in subnet private con IMDSv2 obbligatorio e dischi cifrati, add-on gestiti (VPC CNI, CoreDNS, kube-proxy, Pod Identity Agent, EBS CSI), Pod Identity per i ruoli dei pod; stack separato `kubernetes-addons` (provider Helm) per AWS Load Balancer Controller, Karpenter e KEDA, con versioni bloccate |
| `/kynfra:create-ecr-infra-aws` | repository privati con tag **immutabili**, scansione al push (o enhanced scanning), cifratura KMS, lifecycle policy (scadenza delle immagini non taggate e delle vecchie), policy di pull solo per i ruoli di EKS/Lambda indicati |
| `/kynfra:create-secrets-infra-aws` | Secrets Manager con chiave KMS dedicata (rotazione della chiave attiva), segreti senza valore nei file (sez. 5.3), rotazione automatica dove supportata, resource policy per singolo ruolo, recovery window, replica opzionale in seconda regione |

### 6.1 Flusso di un comando
1. Legge `.kynfra/config.json` (provider, ambienti, regione, naming, tag) e cosa esiste già in `infra_root`
   (es. lo stack `network` richiesto da ELB ed EKS: se manca, propone di generarlo prima).
2. Chiede in **un solo giro di domande** solo ciò che manca (es. per la SPA: dominio, hosted zone esistente o nuova,
   ambienti, se esporre `/api`).
3. Esegue `generate.py`, che copia modulo e stack dai template e compila i `tfvars` per ogni ambiente
   (deterministico: stessa richiesta → stessi file; non sovrascrive file esistenti salvo `--force` dell'utente).
4. Le eventuali personalizzazioni l'agente le fa con gli strumenti di modifica dei file, quindi passano dalle regole.
5. Esegue i controlli (sez. 7.3) e riporta: file creati, output dello stack, comandi che il DevOps dovrà lanciare
   (`init`, `plan`, `apply`), cosa resta manuale (es. delega NS del dominio, valori dei segreti).

### 6.2 Backend completo da un progetto kybes
Il comando backend non produce uno scheletro: legge il contratto di kybes e genera l'infrastruttura di ogni elemento.

| Sorgente kybes | Infrastruttura generata |
|---|---|
| `schemas/openapi.yaml` | API Gateway REST: Terraform legge il file (`yamldecode(file(...))`), aggiunge a ogni operazione l'integrazione AWS e il validatore, e lo passa come `body`. Lo schema resta l'unica fonte: un endpoint nuovo in kybes appare al `plan` successivo senza rigenerare |
| `services/<contesto>/functions/<nome>` | Lambda (runtime e handler dal manifest della function), ruolo IAM, log group, alias `live`, permesso di invocazione da API Gateway, accesso a RDS Proxy e ai segreti del contesto |
| `services/<contesto>/ms/<nome>` | integrazione VPC link → NLB/ALB interno → servizio su EKS, repository ECR, ruolo Pod Identity |
| `jobs/<nome>` | coda SQS + DLQ (o regola EventBridge/schedule), ruolo Pod Identity per lo scaler KEDA e per il job, repository ECR |
| `schemas/db` presente | RDS Proxy, segreto delle credenziali gestito da RDS, security group dal solo backend (il database stesso è fuori dalla v1 salvo richiesta) |

- **Mappatura endpoint → handler**: ogni operazione OpenAPI indica il suo handler con l'estensione
  `x-kybes-handler: <contesto>/functions/<nome>` (o `/ms/<nome>`). Se manca, kynfra la deduce dalla convenzione
  `/v1/<contesto>/...` e chiede conferma per le operazioni ambigue; non inventa mai un handler. La mappatura generata
  vive in `envs/<env>/backend/handlers.auto.tfvars` (rigenerata dal comando, non scritta a mano).
- **Pacchetti delle Lambda**: zip caricati dalla build in un bucket di artefatti (generato dallo stack, privato e
  versionato); Terraform riferisce chiave e hash passati come variabili, non costruisce il codice.
- Regola **`api-coverage`** (block, solo nei repo kybes): ogni operazione di `openapi.yaml` ha un handler esistente e
  ogni function/microservizio/job ha la sua infrastruttura. Lo stop gate la ricontrolla a ogni modifica, così backend
  e infrastruttura non divergono.
- Proposta collaterale per kybes (fuori da questo progetto): far scrivere `x-kybes-handler` al suo architect.

### 6.3 Generatore
`generate.py --pattern <p> --provider aws --env <e>[,<e>] --var k=v …` è l'unico comando che scrive file IaC da shell,
ed è consentito da `bash_guard` come `install.sh`. I template sono già conformi alle regole: la CI del kit genera ogni
pattern in una cartella vuota e verifica che passi tutti i controlli in modalità strict.

## 7. Guardrail

### 7.1 Motore
`hcl.py` estrae da `.tf`, `.tfvars` e `.tf.json` i blocchi (`resource "tipo" "nome"`, `module`, `provider`,
`terraform`, `backend`, `variable`, `data`), gli attributi e i blocchi annidati, con i numeri di riga; le espressioni
restano testo. Basta a verificare presenza e valore di attributi senza dipendenze esterne (solo libreria standard,
come kyfes). Le regole sono funzioni che ricevono i blocchi di un file (pre_write) o dell'intero progetto (stop gate),
così le regole che coinvolgono più risorse (es. il bucket e la sua `aws_s3_bucket_public_access_block`) valutano
l'insieme.

### 7.2 Regole (default `block` salvo indicazione)

**Trasversali**
| Regola | Cosa rifiuta |
|---|---|
| `protected-files` | modifiche ai file protetti (sez. 4.1) |
| `folder-layout` | file IaC fuori da `bootstrap/`, `modules/`, `envs/<env>/<stack>/`, `native/`; ambienti non in config |
| `remote-state` | root module senza backend remoto cifrato con lock; backend locale fuori da `bootstrap/` |
| `version-pinning` | `required_version`/`required_providers` mancanti o senza vincolo; moduli esterni senza versione o ref fissa |
| `static-credentials` | `access_key`/`secret_key`/token nei provider, nei `tfvars` o nelle variabili con default |
| `secrets` | segreti in chiaro (chiavi, password, connection string) in `.tf`, `.tfvars`, `native/`; `secret_string` con letterale; variabili riservate senza `sensitive = true` |
| `required-tags` | provider AWS senza `default_tags` con i tag obbligatori |
| `account-guard` | provider AWS senza `allowed_account_ids` negli stack |
| `variables-typed` | variabili senza `type` o `description` (warn) |
| `literal-reuse` | stesso letterale di dominio (CIDR, domini, nomi, porte) ripetuto in più file invece di `locals`/variabili (warn, block oltre soglia allo stop gate) |
| `scanner-suppression` | commenti `checkov:skip`, `trivy:ignore`, `tflint-ignore` (le eccezioni vivono solo in config, sez. 7.4) |
| `no-provisioners` | `local-exec`/`remote-exec` (comandi fuori dal controllo di Terraform) |

**AWS (`rules_aws.py`)**
| Regola | Cosa rifiuta |
|---|---|
| `s3-private` | bucket senza public access block completo, con ACL pubbliche, senza cifratura, senza policy TLS only; versioning assente su bucket di stato e di contenuto |
| `cloudfront-https` | `viewer_protocol_policy = "allow-all"`, TLS minimo < `TLSv1.2_2021`, origin S3 con OAI o bucket website pubblico invece di OAC, distribuzione senza response headers policy, senza log, senza WAF in prod |
| `lb-https` | listener HTTP che non fa redirect, listener HTTPS senza policy TLS moderna, `drop_invalid_header_fields` disattivo, access log assenti, deletion protection assente in prod |
| `sg-open` | ingress da `0.0.0.0/0`/`::/0` su porte diverse da 80/443, sempre su 22/3389 e porte di database |
| `iam-least-privilege` | `Action = "*"` con `Resource = "*"`, `AdministratorAccess`/`PowerUserAccess`, `iam:PassRole` su `*`, trust policy con principal `*` senza condizioni |
| `kms-rotation` | chiavi KMS senza `enable_key_rotation = true` |
| `logs-retention` | log group senza `retention_in_days` (e senza KMS in prod) |
| `eks-hardening` | endpoint pubblico senza CIDR espliciti, senza cifratura dei Secret, senza log del control plane, node senza IMDSv2 obbligatorio |
| `ecr-hardening` | tag mutabili, scansione disattiva, nessuna lifecycle policy |
| `api-hardening` | route senza authorizer (salvo elenco in config), stage senza throttling o access log |
| `lambda-hardening` | variabili d'ambiente con nomi sensibili e valori letterali, senza tracing, senza log group con retention |
| `region-pinning` | regione o account ID scritti come letterali nei moduli (vanno in variabili/`tfvars`) (warn) |

### 7.3 Controlli dello stop gate e della CI
1. `arch_check.py` (regole di kynfra su tutto `infra_root`).
2. `terraform fmt -check -recursive`.
3. Per ogni stack: `terraform init -backend=false` + `terraform validate`.
4. `tflint --recursive` con il ruleset AWS (config generata dall'installer).
5. Scanner di sicurezza: **Checkov** (default) o **Trivy** (`config`), scelto in config.

Se uno strumento esterno non è installato in locale, lo stop gate lo segnala con il comando per installarlo ma non
blocca su di esso (le regole interne bloccano comunque); in CI invece tutti gli strumenti sono obbligatori e
installati dal workflow. I comandi sono configurabili in `stop_gate.commands`.

### 7.3.1 Strumenti esterni: download tracciato e approvato strumento per strumento
kynfra può scaricare gli strumenti che gli servono (Terraform o OpenTofu, TFLint e il suo ruleset AWS, Checkov o
Trivy), ma **solo con l'approvazione esplicita dell'utente, uno strumento alla volta**, e con traccia di ogni
installazione.

- Comando `/kynfra:tools` (skill `kynfra-tools`) e script `tools.py` (`status`, `install <tool>`): per ogni strumento
  mancante o in versione non conforme mostra nome, versione, sorgente ufficiale, checksum atteso e cartella di
  destinazione, e chiede conferma **per quel solo strumento**. Una risposta vale per uno strumento e una versione: non
  esistono approvazioni cumulative o "sì a tutto".
- Download solo da sorgenti ufficiali elencate nel kit (releases.hashicorp.com, GitHub releases di OpenTofu, TFLint e
  Trivy, PyPI per Checkov in un virtualenv dedicato), con **verifica del checksum** (SHA256SUMS firmati dove
  disponibili); se la verifica fallisce l'installazione si annulla.
- Installazione locale al progetto (`.kynfra/bin/`, ignorata da git), mai globale e mai con `sudo`; lo stop gate usa
  prima quei binari, poi quelli nel `PATH`.
- **Registro** `.kynfra/tools.lock.json` (versionato): per ogni strumento versione, sorgente, checksum, data e chi ha
  approvato (utente git). Lo stop gate e la CI verificano che i binari usati corrispondano al registro.
- Nell'agente: `bash_guard` rifiuta ogni download o installazione di strumenti fuori da `tools.py` (`curl … | sh`,
  `brew install`, `pip install`, `npm i -g`, …). `tools.py install` passa dalla richiesta di permesso del comando
  shell, quindi l'utente lo autorizza ogni volta; la skill esegue un'installazione per comando, mai più strumenti
  insieme. In CI il workflow installa le versioni del registro, senza approvazioni interattive.

### 7.4 Eccezioni
**Baseline del kit**: per lo scanner il kit fornisce un elenco versionato di controlli esclusi, ciascuno motivato e
legato a un ambiente (es. WAF non richiesto in `dev`, replica cross-region del bucket non richiesta) o fuori perimetro.
Vive nel kit (`tools/kynfra/`, protetto), non nel progetto, ed è lo stesso con cui la CI del kit verifica i template.

Nessuna soppressione inline. Un'eccezione è una voce in `.kynfra/config.json`
(`exceptions: [{rule, path, resource, reason, expires}]`) che solo l'utente può scrivere (file protetto); scaduta
`expires`, la regola torna a bloccare. Le severità per regola (`rules: {"<regola>": "warn"}`) si cambiano allo stesso
modo.

### 7.5 Shell (`bash_guard.py`)
Oltre a ciò che fa kyfes (scritture da shell nei file sotto `infra_root`, file protetti, `git apply`, `install.sh
--force/--uninstall`), rifiuta:
- `terraform`/`tofu` `apply`, `destroy`, `import`, `taint`, `untaint`, `state` (salvo `list`/`show`), `force-unlock`,
  `workspace new|delete`, `init` con backend reale (consentito solo `init -backend=false`), `plan` (richiede
  credenziali: lo lancia il DevOps);
- CLI cloud in modalità mutante: `aws` (consentiti solo `get-*`, `describe-*`, `list-*`, `sts get-caller-identity`),
  `az`, `gcloud`, `vercel`, `kubectl` (salvo `get`/`describe`/`explain`), `helm` (salvo `template`/`lint`/`show`).

### 7.6 Proprietà dei moduli generati
Dopo la generazione `modules/` ed `envs/` sono codice del progetto: l'agente li può modificare, sempre passando dalle
regole. Ogni file generato riporta in testa la versione di kynfra e il pattern. `generate.py --upgrade` confronta i
moduli con i template della versione installata e mostra le differenze, senza sovrascrivere le personalizzazioni.

## 8. Skill e agenti

| Elemento | Ruolo |
|---|---|
| `kynfra-architecture` | regole vincolanti (sez. 5 e 7 in forma operativa), checklist, formato del piano; `references/aws.md` con nomi esatti di risorse e argomenti per pattern |
| `kynfra-init` | installazione guidata (rileva il contesto, chiede solo ciò che manca, lancia l'installer) |
| `kynfra-plan` / agente `architect` | piano conforme, senza scrivere file |
| agente `implementer` | implementa un task del piano rispettando le regole |
| `kynfra-review` / agente `reviewer` | revisione indipendente, esito APPROVATO / DA CORREGGERE |
| `create-<pattern>-infra-aws` | i sette comandi della sez. 6 |

**Formato obbligatorio del piano**: tabella `Risorsa | Pattern/modulo | Stack | Ambienti | Differenze tra ambienti |
Controlli di sicurezza | Dipendenze (remote state)`, seguita da: variabili e output nuovi, segreti coinvolti e come
arrivano il valore, impatto sui costi (risorse a costo fisso: NAT, EKS, ALB, WAF), comandi che il DevOps dovrà
eseguire, violazioni richieste e alternative conformi, task piccoli e indipendenti.

Le versioni delle API cambiano: skill e agenti consultano la documentazione aggiornata (Context7 o registry Terraform)
prima di usare argomenti di cui non sono certi; le regole non cambiano con la versione.

## 9. Test e CI del kit
- `tests/hooks/`: unittest del parser HCL, di ogni regola (casi conformi e non), di pre_write sul file risultante,
  di bash_guard (comandi consentiti e rifiutati), dello stop gate, dell'installer (Claude Code e Codex, rilevamento
  kybes/kyfes).
- `tests/patterns/`: per ogni pattern genera in una cartella vuota con più ambienti e verifica `arch_check --strict`
  a zero violazioni; poi `terraform fmt -check`, `init -backend=false`, `validate`, `tflint`, `checkov`.
- `.github/workflows/kit-tests.yml`: job `hooks` + matrice dei pattern, con Terraform, TFLint e Checkov installati.
- Template CI per i progetti utente: `templates/ci/kynfra-check.yml` (stessi controlli, nessun accesso al cloud).

## 10. Documentazione
`README.md` in inglese con banner (come kyfes) e `docs/` in italiano: architettura, configurazione, controlli, pattern
AWS (uno per pattern, con diagramma Mermaid), segreti, sviluppo del kit, Codex, roadmap.

## 11. Roadmap dopo la v1
1. Pipeline: GitHub Actions con OIDC verso AWS, `plan` sulle PR, `apply` con approvazione per `prod`; poi Azure
   DevOps e GitLab.
2. Azure: stessi pattern (Storage + Front Door, APIM + Functions, Application Gateway, AKS, ACR, Key Vault, VNet).
3. Vercel (provider Terraform + `vercel.json`), poi GCP e Cloudflare.
4. Stima dei costi (Infracost), rilevamento del drift, policy as code aggiuntive (OPA/Conftest).

## 12. Scelte fatte da me (da verificare)
- Nome dei comandi in kebab-case (`/kynfra:create-spa-infra-aws`): i nomi delle skill non ammettono `_`.
- Moduli scritti con risorse native del provider, **senza moduli di terze parti** (es. `terraform-aws-modules`): tutto
  il codice è sotto le regole di kynfra e non dipende da codice esterno.
- Uno stack (e uno stato) per pattern e ambiente, collegati con `terraform_remote_state`.
- Stato S3 con lock nativo (`use_lockfile`), senza DynamoDB.
- Checkov come scanner di default (Trivy in alternativa); strumenti esterni non bloccanti in locale se mancano,
  obbligatori in CI.
- Requisiti di kybes adottati come default (REST API con validazione, RDS Proxy, Karpenter, KEDA); in un repo kybes è
  kynfra a scrivere `infra/`.
- Lambda distribuite come zip da un bucket di artefatti; mappatura degli handler con `x-kybes-handler`.
- Baseline di eccezioni dello scanner fornita dal kit; eccezioni del progetto solo dall'utente.
- Moduli generati di proprietà del progetto, con aggiornamento tramite confronto.
- Regione di default `eu-south-1` (Milano), modificabile in installazione.
- `plan` non consentito all'agente (servono credenziali): lo esegue il DevOps.

## 13. Lasciato al costruttore
- Struttura interna di `rules.py`/`hcl.py` e dei test, purché solo libreria standard.
- Versioni esatte di Terraform, provider AWS/Helm, add-on EKS, TFLint e Checkov: le più recenti stabili al momento
  dell'implementazione, verificate sulla documentazione.
- Testo esatto di skill, agenti e documentazione, sul tono di kyfes.
- Diagrammi e banner.
