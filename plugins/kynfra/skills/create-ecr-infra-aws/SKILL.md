---
name: create-ecr-infra-aws
description: Generate a shared AWS ECR registry with kynfra (private repositories with immutable tags, scan on push, dedicated KMS key with rotation, lifecycle policies, pull-only repository policy with deny outside the account) as a single shared stack. Use when the user runs /kynfra:create-ecr-infra-aws or asks for ECR, a container registry or a place to push Docker images on AWS.
---

# Creare il registry ECR su AWS (pattern `ecr`)

Genera il modulo `modules/ecr` e lo stack condiviso `envs/shared/ecr` (una sola volta, condiviso tra gli ambienti; chiave di stato `<progetto>/shared/ecr.tfstate`). Prima di scrivere o modificare codice carica le regole della skill `kynfra-architecture` (`SKILL.md` e `references/aws.md`, sezione `ecr`). Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

1. **Leggi lo stato**: `.kynfra/config.json` (`infra_root`, `project`, `region`, `environments`, `accounts`, `tags`, `iac`; nei repository kybes anche `kybes`) e cosa esiste già sotto `infra_root`: `envs/shared/ecr`, `bootstrap/`, gli stack dei workload (EKS, Lambda) i cui ruoli faranno il pull. Se `bootstrap/` manca, segnala che il backend S3 dello stato deve esistere prima dell'`init` e proponi di generarlo (`generate.py --pattern bootstrap`). Il pattern `ecr` non ha `requires`. Se `envs/shared/ecr` esiste già, non rigenerarlo: modifica i file con gli strumenti di modifica.
2. **Un solo giro di domande**, solo su ciò che manca:
   - `repositories`: nomi in kebab-case separati da virgola (es. `api,worker`). Nei repository kybes il default è un repository per ogni `services/*/ms/*` e `jobs/*` (nome della cartella); se non puoi derivarli, chiedili;
   - `pull_principals` (facoltativo, default vuoto): ARN di ruoli IAM dell'account che devono fare il pull (nodi EKS, Lambda), se esistono già; i ruoli dei workload possono anche avere una policy identity;
   - `untagged_expiry_days` (default 7) e `keep_last` (default 30).
   Non chiedere gli ambienti: lo stack è unico e non vuole `--env`. Con più account nella config, l'account dello stack condiviso si indica con `--var account=<nome>`.
3. **Genera**:

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern ecr --provider aws --var repositories=api,worker [--var pull_principals=arn:aws:iam::<account>:role/<nome>] [--var untagged_expiry_days=7] [--var keep_last=30]
   ```

   Il generatore non sovrascrive file esistenti salvo `--force`, che chiede l'utente. Per vedere le differenze con una versione più recente del kit: `--upgrade`.
4. **Personalizzazioni** solo con gli strumenti di modifica dei file, mai con redirect o `sed -i` da shell. Mantieni tag `IMMUTABLE`, `scan_on_push = true`, cifratura KMS con la chiave dedicata (`enable_key_rotation = true`), `force_delete = false`, una lifecycle policy per ogni repository e il deny fuori dall'account nella repository policy. Lo stack `ecr` non legge mai lo stato di altri stack: non aggiungere `terraform_remote_state` verso i workload; sono loro a leggere gli output di ECR.
5. **Controlla**: `python3 -B <kit>/scripts/arch_check.py . --external` e correggi la causa di ogni finding (mai soppressioni inline). Se mancano strumenti esterni proponi `/kynfra:kynfra-tools`.
6. **Riepiloga** in poche righe:
   - file creati (modulo, stack condiviso) e output dello stack: `repository_urls` (nome => URL), `repository_arns`, `kms_key_arn`, `registry_id`;
   - lettura in un solo verso: lo stack `ecr` si applica per primo; gli stack dei workload (EKS, Lambda) leggono `repository_urls` e `repository_arns` con `terraform_remote_state` (chiave `<progetto>/shared/ecr.tfstate`) e danno al proprio ruolo il pull; il push non è nella repository policy: i ruoli di CI hanno una policy identity con `ecr:GetAuthorizationToken` (su `*`) e, sull'ARN del repository, `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:BatchCheckLayerAvailability`; i tag sono immutabili, quindi ogni push usa un tag unico (es. lo SHA del commit);
   - costi: storage delle immagini (limitato dalla lifecycle policy), trasferimento dati e la chiave KMS;
   - comando che esegue il DevOps con le sue credenziali (tu non lo lanci): `cd <infra_root>/envs/shared/ecr && terraform init && terraform plan -out=ecr.tfplan && terraform apply ecr.tfplan` (o `tofu`);
   - passi manuali, solo del DevOps: aggiungere i ruoli di pull in `pull_principals` quando esistono (opzionale), creare le policy identity dei ruoli di CI per il push.
