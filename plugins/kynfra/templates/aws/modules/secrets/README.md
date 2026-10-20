# Modulo `secrets`

Secrets Manager come "secret vault": i segreti sono contenitori senza valore, cifrati con una chiave KMS dedicata.

- Chiave KMS multi-regione con rotazione attiva e alias `<progetto>-<env>-secrets`. La policy della chiave dà l'amministrazione alla radice dell'account (quindi i ruoli dell'account possono usarla con una policy identity) e `Decrypt` ai `readers` dei segreti, solo tramite Secrets Manager della regione (`kms:ViaService`).
- `aws_secretsmanager_secret` `<progetto>/<env>/<nome>` con `kms_key_id`, `recovery_window_in_days` (7-30; in prod 30). Con `replica_region` (diversa dalla regione dello stack) la chiave ha una replica (`aws_kms_replica_key`, provider `aws.replica`) usata dalla replica dei segreti.
- Nessuna `aws_secretsmanager_secret_version`: il valore lo inserisce il DevOps fuori da Terraform (`aws secretsmanager put-secret-value`).
- Lettura, in un solo verso: lo stack `secrets` si applica per primo e non legge lo stato di altri stack. Gli stack dei workload leggono `secret_arns` e `kms_key_arn` con `terraform_remote_state` e danno al proprio ruolo una policy identity: `secretsmanager:GetSecretValue` sull'ARN del segreto e `kms:Decrypt` sulla chiave con `kms:ViaService = secretsmanager.<regione>.amazonaws.com`.
- `readers` è una concessione facoltativa in più nella resource policy, con ARN di ruoli dell'account già esistenti (aggiunti in un secondo momento). Non è esclusiva: nello stesso account anche le policy identity dei ruoli danno accesso. La resource policy aggiunge sempre il deny per i principal fuori dall'account (servizi AWS esclusi) e per il traffico non TLS.
- Rotazione (`aws_secretsmanager_secret_rotation`) solo per i segreti con `rotation_lambda_arn`, ogni `rotation_days` (in prod al massimo 30). La Lambda è di un altro stack e le serve: un ruolo con `secretsmanager:DescribeSecret`, `GetSecretValue`, `PutSecretValue`, `UpdateSecretVersionStage` sul segreto (più `GetRandomPassword`) e `kms:Decrypt`/`kms:GenerateDataKey` sulla chiave, e un `aws_lambda_permission` che permette `secretsmanager.amazonaws.com` di invocarla (`principal = "secretsmanager.amazonaws.com"`, `source_account` dell'account).

Output: `secret_arns` (nome => ARN), `secret_names` (nome => nome completo), `kms_key_arn`.
