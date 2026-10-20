# Modulo `ecr`

Registry privato di container condiviso tra gli ambienti (stack `envs/shared/ecr`, chiave di stato `<progetto>/shared/ecr.tfstate`).

- Chiave KMS dedicata con rotazione attiva e alias `<progetto>-<env>-ecr`; policy della chiave: amministrazione alla radice dell'account (ECR la usa con grant a nome del chiamante).
- Un `aws_ecr_repository` per nome in `repositories`, chiamato `<progetto>/<nome>`: tag `IMMUTABLE`, scansione al push, cifratura KMS con la chiave dedicata, `force_delete = false`.
- `aws_ecr_lifecycle_policy` per ogni repository: le immagini non taggate scadono dopo `untagged_expiry_days` (7), restano le ultime `keep_last` (30) taggate.
- `aws_ecr_repository_policy` per ogni repository: pull (`GetDownloadUrlForLayer`, `BatchGetImage`, `BatchCheckLayerAvailability`) solo per i ruoli di `pull_principals` (dello stesso account; vuoto = nessuna concessione), più un deny per i principal fuori dall'account (servizi AWS esclusi con `BoolIfExists` su `aws:PrincipalIsAWSService`, così replica e scansione non si rompono). Nessun accesso pubblico. Il push non è concesso dalla policy: i ruoli di CI usano policy identity (`ecr:GetAuthorizationToken` su `*`, `ecr:PutImage`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:BatchCheckLayerAvailability` sull'ARN del repository).
- Lettura in un solo verso: lo stack `ecr` non legge mai lo stato di altri stack; i workload (EKS, Lambda) leggono `repository_urls` e `repository_arns` con `terraform_remote_state` (chiave `<progetto>/shared/ecr.tfstate`).

Output: `repository_urls` (nome => URL), `repository_arns`, `kms_key_arn`, `registry_id` (ID dell'account).
