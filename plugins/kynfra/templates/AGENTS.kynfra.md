<!-- kynfra:start (blocco gestito dall'installer: modifiche qui vengono sovrascritte) -->
## Regole infrastruttura (kynfra)

Questo progetto genera Terraform per AWS con le regole di kynfra (IaC: __IAC__, radice dell'infrastruttura: `__INFRA_ROOT__`). In sintesi:

- **Alberatura fissa** sotto `__INFRA_ROOT__`: `bootstrap/`, `modules/<pattern>/`, `envs/<env>/<stack>/`, `envs/shared/<stack>/`, `native/<pattern>/`. Uno stack per pattern e ambiente; differenze tra ambienti solo nei `tfvars`; moduli solo con risorse native dei provider.
- **Stato remoto** S3 con `encrypt = true` e `use_lockfile = true`, chiave `<progetto>/<env>/<stack>.tfstate`; mai backend locale fuori da `bootstrap/`. Versioni bloccate (`required_version`, `required_providers` con `~>`, lock file committato).
- **Provider AWS** con `default_tags` (`Project`, `Environment`, `Owner`, `CostCenter`, `ManagedBy = "kynfra"`) e `allowed_account_ids`; nessuna credenziale statica. Nomi delle risorse prefissati `<progetto>-<env>`; `account_id` e regione sempre da variabili, mai nei moduli.
- **Segreti**: mai in chiaro nei file; solo contenitori (`aws_secretsmanager_secret`), valori inseriti fuori da Terraform. Variabili riservate con `sensitive = true`.
- **Sicurezza AWS**: S3 privato e cifrato, CloudFront/ALB solo HTTPS, security group senza `0.0.0.0/0` su porte non web, IAM a privilegi minimi, rotazione KMS, retention dei log, hardening di EKS/ECR/API/Lambda. Valori ripetuti in `locals` o variabili, non come letterali.
- **Niente soppressioni inline** (`checkov:skip`, `trivy:ignore`, `tflint-ignore`): le eccezioni stanno solo in `.kynfra/config.json` (`exceptions`) e le scrive l'utente.
- **Mai eseguire** `apply`, `destroy`, `import`, `taint`, `plan`, `force-unlock`, `init` senza `-backend=false`, né CLI cloud mutanti: lo fa il DevOps.

Modo di lavorare:
- Comandi: `/kynfra:create-<pattern>-infra-aws` con pattern `network`, `spa`, `backend`, `elb`, `eks`, `ecr`, `secrets`; `/kynfra:tools` per gli strumenti esterni.
- Pianifica con l'agente **kynfra:architect** (Claude Code) o la skill **$kynfra-plan** (Codex), non con il planner integrato.
- Implementa un task alla volta con **kynfra:implementer** / l'agente Codex `kynfra_implementer`.
- Fai verificare con **kynfra:reviewer** / **$kynfra-review**.
- Strumenti esterni (Terraform, TFLint, ruleset AWS, Checkov): si installano solo con `tools.py install <strumento>`, uno alla volta, con l'approvazione esplicita dell'utente per quello strumento. Mai `curl | sh`, `brew install`, `pip install`.
- Gli hook rifiutano le scritture non conformi e bloccano la chiusura finché `arch_check`, fmt, validate, tflint e scanner non passano: correggi la causa, non aggirarli. Il codice si scrive con gli strumenti di modifica dei file, non da shell.
- Configurazione e kit: `.kynfra/config.json` (la modifica solo l'utente, come `tools/kynfra/` e le impostazioni e gli hook dell'agente). Controllo completo: `python3 -B tools/kynfra/plugins/kynfra/scripts/arch_check.py .`
<!-- kynfra:end -->
