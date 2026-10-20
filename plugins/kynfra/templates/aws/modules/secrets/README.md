# Modulo `secrets`

Secrets Manager come "secret vault": i segreti sono contenitori senza valore, cifrati con una chiave KMS dedicata.

- Chiave KMS con rotazione attiva e alias `<progetto>-<env>-secrets`; la policy della chiave dà l'amministrazione alla radice dell'account e `Decrypt` ai soli `readers` dei segreti, solo tramite Secrets Manager della regione (`kms:ViaService`).
- `aws_secretsmanager_secret` `<progetto>/<env>/<nome>` con `kms_key_id`, `recovery_window_in_days` (7-30; in prod 30) e replica opzionale (`replica_region`, chiave gestita `aws/secretsmanager` nella regione di replica).
- Nessuna `aws_secretsmanager_secret_version`: il valore lo inserisce il DevOps fuori da Terraform (`aws secretsmanager put-secret-value`).
- Resource policy per segreto: `GetSecretValue`/`DescribeSecret` solo ai `readers` (ruoli IAM dell'account), deny per i principal fuori dall'account e per il traffico non TLS.
- Rotazione (`aws_secretsmanager_secret_rotation`) solo per i segreti con `rotation_lambda_arn`; ogni `rotation_days` (in prod al massimo 30).

Output: `secret_arns` (nome => ARN), `kms_key_arn`.
