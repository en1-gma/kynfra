---
name: create-secrets-infra-aws
description: Generate an AWS secret vault with kynfra (Secrets Manager secrets without values, dedicated KMS key with rotation, per-role resource policies, recovery window, optional rotation Lambda and cross-region replica) as a secrets stack per environment. Use when the user runs /kynfra:create-secrets-infra-aws or asks for Secrets Manager, secret storage or a place for passwords/API keys on AWS.
---

# Creare il vault dei segreti su AWS (pattern `secrets`)

Genera il modulo `modules/secrets` e lo stack `envs/<env>/secrets` per ogni ambiente richiesto. Prima di scrivere o modificare codice carica le regole della skill `kynfra-architecture` (`SKILL.md` e `references/aws.md`, sezione `secrets`). Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

Regola di fondo: nessun valore di segreto nei file, nei tfvars, nei comandi o nella conversazione. I segreti sono contenitori; il valore lo inserisce il DevOps fuori da Terraform.

1. **Leggi lo stato**: `.kynfra/config.json` (`infra_root`, `project`, `region`, `environments`, `accounts`, `tags`, `iac`) e cosa esiste già sotto `infra_root`: `envs/*/secrets`, `bootstrap/`, e gli stack dei workload che leggeranno i segreti (ruoli IAM di Lambda, EKS, ecc.). Se `bootstrap/` manca, segnala che il backend S3 dello stato deve esistere prima dell'`init` e proponi di generarlo (`generate.py --pattern bootstrap`). Il pattern `secrets` non ha `requires`.
2. **Un solo giro di domande**, solo su ciò che manca:
   - ambienti da generare (default: tutti quelli in config);
   - quali segreti servono (nome in minuscolo con trattini, descrizione) e l'eventuale Lambda di rotazione per segreto: servono per modificare il `terraform.tfvars` al passo 4. I lettori NON si chiedono qui: i workload leggono con la policy identity del proprio ruolo (passo 6);
   - `recovery_window_days` (default 7, 30 in prod, ammessi 7-30);
   - `replica_region` (default vuoto): regione di replica dei segreti, se serve disponibilità tra regioni.
3. **Genera**:

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern secrets --provider aws --env dev,prod [--var recovery_window_days=14] [--var replica_region=eu-west-1]
   ```

   Il generatore non sovrascrive file esistenti salvo `--force`, che chiede l'utente. Per vedere le differenze con una versione più recente del kit: `--upgrade`.
4. **Personalizzazioni** solo con gli strumenti di modifica dei file, mai con redirect o `sed -i` da shell. Il generatore non passa strutture: il `terraform.tfvars` di ogni ambiente contiene la mappa `secrets` di esempio con un solo segreto `app-db` e `readers = []`. Modificala con gli strumenti di modifica: un elemento per segreto (`description`; `rotation_lambda_arn` facoltativo per la rotazione automatica; `readers` facoltativo, lista di ARN di ruoli IAM già esistenti dell'account, per una concessione in più nella resource policy, da aggiungere anche in un secondo momento). Lo stack `secrets` non legge mai lo stato di altri stack: non aggiungere `terraform_remote_state` verso i workload. Mantieni la chiave KMS dedicata con `enable_key_rotation = true`, il deny fuori dall'account e senza TLS, e nessuna `aws_secretsmanager_secret_version` con `secret_string`.
5. **Controlla**: `python3 -B <kit>/scripts/arch_check.py . --external` e correggi la causa di ogni finding (mai soppressioni inline). Se mancano strumenti esterni proponi `/kynfra:kynfra-tools`.
6. **Riepiloga** in poche righe:
   - file creati (modulo, stack per ambiente) e output di ogni stack: `secret_arns` (nome => ARN), `secret_names` (nome => nome completo) e `kms_key_arn`;
   - lettura in un solo verso: lo stack `secrets` si applica per primo; gli stack dei workload (Lambda, EKS, ecc.) leggono gli output con `terraform_remote_state` (chiave `<progetto>/<env>/secrets.tfstate`) e danno al proprio ruolo una policy identity con `secretsmanager:GetSecretValue` sull'ARN del segreto e `kms:Decrypt` sulla chiave con `kms:ViaService = secretsmanager.<regione>.amazonaws.com`; l'ARN va ai workload come `DB_SECRET_ARN`;
   - costi: ogni segreto ha un costo mensile, più le chiamate API e la chiave KMS; la replica raddoppia il costo del segreto e aggiunge una replica della chiave;
   - comandi che esegue il DevOps con le sue credenziali (tu non li lanci): per ogni ambiente `cd <infra_root>/envs/<env>/secrets && terraform init && terraform plan -out=secrets.tfplan && terraform apply secrets.tfplan` (o `tofu`);
   - passi manuali, solo del DevOps: inserire il valore di ogni segreto fuori da Terraform, es. `aws secretsmanager put-secret-value --secret-id <progetto>/<env>/<nome> --secret-string <valore>` (la shell dell'agente rifiuta letture e scritture di segreti, e il valore non deve comparire in file o conversazione); con `rotation_lambda_arn`, la Lambda (di un altro stack) ha bisogno di un ruolo con `secretsmanager:DescribeSecret`, `GetSecretValue`, `PutSecretValue`, `UpdateSecretVersionStage` sul segreto, `secretsmanager:GetRandomPassword`, `kms:Decrypt` e `kms:GenerateDataKey` sulla chiave, e di un `aws_lambda_permission` con `principal = "secretsmanager.amazonaws.com"` (e `source_account`); `readers`, se servono, si aggiungono dopo con ARN di ruoli esistenti.
