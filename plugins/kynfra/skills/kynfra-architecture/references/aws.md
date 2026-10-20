# kynfra — riferimento AWS

Per ogni pattern: risorse e argomenti chiave con i valori che le regole richiedono. I valori in grassetto-codice sono letterali obbligatori. **I nomi degli argomenti cambiano tra le versioni del provider `aws`: prima di usarli verifica su Context7 o sul registry Terraform la documentazione della versione bloccata nel progetto** (`templates/versions.json`). Ogni risorsa ha i tag da `default_tags` e un nome `<progetto>-<env>-...`.

## Fondamenta (tutti gli stack)

- `terraform { required_version = "~> X.Y"  required_providers { aws = { source = "hashicorp/aws" version = "~> X.Y" } } }`
- `backend "s3" { bucket, key = "<progetto>/<env>/<stack>.tfstate", region, encrypt = true, use_lockfile = true }`
- `provider "aws" { region = var.region  allowed_account_ids = [var.account_id]  default_tags { tags = { Project = ..., Environment = ..., Owner = ..., CostCenter = ..., ManagedBy = "kynfra" } } }` (chiavi letterali).
- `bootstrap/`: `aws_s3_bucket` dello stato, `aws_s3_bucket_versioning` (`status = "Enabled"`), `aws_s3_bucket_server_side_encryption_configuration` (`sse_algorithm = "aws:kms"`), `aws_s3_bucket_public_access_block` (4 flag `true`), `aws_s3_bucket_policy` con `Deny` su `s3:*` se `aws:SecureTransport = "false"`, `aws_kms_key` con `enable_key_rotation = true`.
- Bucket S3 in qualsiasi pattern: stesse cinque risorse del bootstrap. Non usare ACL; `aws_s3_bucket_ownership_controls` con `object_ownership = "BucketOwnerEnforced"`.
- KMS: `aws_kms_key` con `enable_key_rotation = true`, `deletion_window_in_days`, policy con `jsonencode`; `aws_kms_alias`.
- Log group: `aws_cloudwatch_log_group` con `retention_in_days` (30/90/365, mai 0); in prod `kms_key_id` tramite variabile ammessa (`kms_key_arn`).

## network

VPC su 2-3 AZ, subnet pubbliche, private e isolate (dati), NAT (uno per AZ in prod, uno altrove), endpoint VPC, flow log cifrati.
- `aws_vpc` (`enable_dns_support = true`, `enable_dns_hostnames = true`), `aws_internet_gateway`, `aws_subnet` (`map_public_ip_on_launch = false` anche nelle pubbliche salvo necessità), `aws_route_table`, `aws_route_table_association`.
- `aws_eip` + `aws_nat_gateway`: `for_each` sulle AZ; in non-prod un solo NAT (variabile `nat_per_az`).
- `aws_vpc_endpoint`: gateway per S3; interface (`vpc_endpoint_type = "Interface"`, `private_dns_enabled = true`, security group dedicato) per `ecr.api`, `ecr.dkr`, `secretsmanager`, `sts`, `logs`.
- `aws_default_security_group` senza regole `ingress` ed `egress`.
- `aws_flow_log` (`traffic_type = "ALL"`, `log_destination_type = "cloud-watch-logs"`) con `aws_cloudwatch_log_group` (retention, KMS in prod) e ruolo IAM minimo.
- Security group: ingress solo da security group sorgenti o CIDR interni (`sg-open`).
- Output per gli altri stack: `vpc_id`, subnet per livello, CIDR.

## spa

S3 privato + CloudFront con OAC, ACM in `us-east-1`, Route53, routing client-side con CloudFront Function, headers di sicurezza, WAF in prod.
- Bucket (fondamenta) con **public access block a 4 flag**, versioning, cifratura, policy TLS only; policy che consente `s3:GetObject` solo al principal `cloudfront.amazonaws.com` con `Condition` `AWS:SourceArn` = ARN della distribuzione.
- `aws_cloudfront_origin_access_control`: `origin_access_control_origin_type = "s3"`, `signing_behavior = "always"`, `signing_protocol = "sigv4"`.
- `aws_cloudfront_distribution`: origin `domain_name = <bucket>.bucket_regional_domain_name` con `origin_access_control_id` (mai `s3_origin_config`, mai endpoint website); `default_cache_behavior { viewer_protocol_policy = "redirect-to-https"  response_headers_policy_id = ...  cache_policy_id = ...  function_association { event_type = "viewer-request" ... } }`; `viewer_certificate { acm_certificate_arn = ...  ssl_support_method = "sni-only"  minimum_protocol_version = "TLSv1.2_2021" }`; `logging_config { bucket = ... }`; `web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.<nome>[0].arn : null`; `aliases`, `default_root_object = "index.html"`. Nessun `custom_error_response` 403/404 che maschera le API.
- `aws_cloudfront_function` (`runtime = "cloudfront-js-2.0"`, `publish = true`): riscrive in `/index.html` le richieste senza estensione.
- `aws_cloudfront_response_headers_policy`: `strict_transport_security` (HSTS), `content_security_policy`, `content_type_options { override = true }`, `frame_options` o `frame-ancestors`.
- `aws_cloudfront_cache_policy`: asset immutabili a lungo, `index.html` senza cache.
- `aws_acm_certificate` (provider `us_east_1`, `validation_method = "DNS"`), `aws_route53_record` di validazione, `aws_acm_certificate_validation`.
- `aws_route53_record` alias A e AAAA verso la distribuzione.
- WAF: `aws_wafv2_web_acl` con `scope = "CLOUDFRONT"` (provider `us_east_1`), managed rule group `AWSManagedRulesCommonRuleSet`; attivo in prod via `waf_enabled`.
- Opzionale `/api/*`: secondo origin (API Gateway) e `ordered_cache_behavior`, sempre `redirect-to-https`.

## backend

Infrastruttura completa letta dal progetto kybes: `schemas/openapi.yaml`, `services/<contesto>/functions|ms/<nome>`, `jobs/<nome>`, `schemas/db`. Regola `api-coverage`.
- `aws_api_gateway_rest_api` con `body = jsonencode(...)` ricavato da `yamldecode(file("<openapi>"))` (l'unico `file()` ammesso: non è una policy IAM), integrazione AWS_PROXY e validatore su ogni operazione; `aws_api_gateway_deployment`, `aws_api_gateway_stage` con `access_log_settings { destination_arn  format = jsonencode({... correlationId ...}) }` e `xray_tracing_enabled = true`; `aws_api_gateway_method_settings` (`method_path = "*/*"`, `throttling_rate_limit`, `throttling_burst_limit`); versione `/v1`.
- Authorizer: `aws_api_gateway_authorizer` (`type = "COGNITO_USER_POOLS"` o JWT/`REQUEST` per OIDC); ogni metodo con `authorization` diversa da `NONE`; route davvero pubbliche solo in `public_routes` di config.
- WAF: `aws_wafv2_web_acl` (`scope = "REGIONAL"`) con `aws_wafv2_web_acl_association`.
- Per ogni function: `aws_lambda_function` (`timeout` breve: raccomandazione di kybes (<= 10 s), non una regola di kynfra; `tracing_config { mode = "Active" }`, `s3_bucket`/`s3_key`/`source_code_hash` da variabili, `role`), `aws_cloudwatch_log_group` `/aws/lambda/<nome>` con `retention_in_days`, `aws_iam_role` + policy minima (`jsonencode`), `aws_lambda_alias` `live`, `aws_lambda_permission` per API Gateway. Variabili d'ambiente senza segreti: solo ARN del segreto (`DB_SECRET_ARN`).
- Microservizi su EKS: `aws_api_gateway_vpc_link` verso NLB/ALB interno, `aws_ecr_repository` (vedi ecr), ruolo Pod Identity (`aws_eks_pod_identity_association`).
- Job: `aws_sqs_queue` + DLQ (`redrive_policy`, `sqs_managed_sse_enabled = true`), ruoli Pod Identity per KEDA e job; `aws_cloudwatch_event_rule` per gli schedule.
- DB: `aws_db_proxy` con `require_tls = true`, segreto gestito da RDS (`manage_master_user_password = true`), security group dal solo backend.
- Bucket artefatti Lambda: bucket privato versionato (fondamenta).

## elb

- `aws_lb` (`load_balancer_type = "application"`, `drop_invalid_header_fields = true`, `enable_deletion_protection = var.deletion_protection` con `true` nei tfvars di prod, `access_logs { bucket = ...  enabled = true }`, `internal` da variabile); NLB solo su richiesta.
- `aws_lb_listener` 80: `default_action { type = "redirect" redirect { protocol = "HTTPS" port = "443" status_code = "HTTP_301" } }`.
- `aws_lb_listener` 443: `protocol = "HTTPS"`, `ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"`, `certificate_arn` (ACM), `default_action` fixed-response 404 o forward.
- `aws_lb_target_group` con `health_check { path  matcher  healthy_threshold  unhealthy_threshold }`, `target_type` (`ip` per EKS).
- `aws_security_group` con ingress 443 e 80 dal mondo, oppure solo dalla prefix list gestita di CloudFront (`aws_ec2_managed_prefix_list` data source); egress verso i target.
- Bucket dei log ALB: privato, versionato, con policy che consente il servizio di log del load balancer; cifratura SSE-S3 (`AES256`) richiesta da ALB.
- WAF: `aws_wafv2_web_acl` regionale + `aws_wafv2_web_acl_association`, attivo in prod.
- Dipendenze: `network` (VPC, subnet) via `terraform_remote_state`.

## eks

- `aws_eks_cluster`: `vpc_config { subnet_ids (private)  endpoint_private_access = true  endpoint_public_access = false (oppure public_access_cidrs espliciti, mai 0.0.0.0/0) }`, `encryption_config { resources = ["secrets"]  provider { key_arn = aws_kms_key.<nome>.arn } }` (KMS con `enable_key_rotation = true`), `enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]`, `access_config { authentication_mode = "API" }`; log group `/aws/eks/<cluster>/cluster` con retention.
- `aws_eks_access_entry` + `aws_eks_access_policy_association` (non `aws-auth`).
- `aws_launch_template` con `metadata_options { http_tokens = "required"  http_put_response_hop_limit = 1 }` e `block_device_mappings { ebs { encrypted = true  kms_key_id = ... } }`; `aws_eks_node_group` (subnet private, `launch_template { id  version }`).
- Karpenter: ruolo del nodo, ruolo del controller con Pod Identity, coda SQS per gli eventi di interruzione, regole EventBridge; nodi gestiti da Karpenter con lo stesso IMDSv2 obbligatorio.
- `aws_eks_addon`: `vpc-cni`, `coredns`, `kube-proxy`, `eks-pod-identity-agent`, `aws-ebs-csi-driver`, con `addon_version` fissata da `versions.json`.
- `aws_eks_pod_identity_association` per i ruoli dei pod; ruoli con trust `pods.eks.amazonaws.com`.
- Stack separato `kubernetes-addons` (provider `helm`, versioni bloccate): AWS Load Balancer Controller, Karpenter, KEDA con `helm_release` e `version` fissa. Il provider si autentica con `aws eks get-token` via `exec` o dati del cluster, non con credenziali statiche.
- Dipendenze: `network`.

## ecr

- `aws_ecr_repository`: `image_tag_mutability = "IMMUTABLE"`, `image_scanning_configuration { scan_on_push = true }` (oppure `aws_ecr_registry_scanning_configuration` con `scan_type = "ENHANCED"`), `encryption_configuration { encryption_type = "KMS"  kms_key = aws_kms_key.<nome>.arn }` con `enable_key_rotation = true`.
- `aws_ecr_lifecycle_policy` (`policy = jsonencode({ rules = [...] })`): scadenza delle immagini non taggate (`tagStatus = "untagged"`, `countType = "sinceImagePushed"`) e conservazione delle ultime N taggate.
- `aws_ecr_repository_policy` con `jsonencode`: pull (`ecr:GetDownloadUrlForLayer`, `ecr:BatchGetImage`, `ecr:BatchCheckLayerAvailability`) solo per i principal indicati (ruoli di EKS/Lambda), mai `Principal = "*"` senza condizioni.
- Stack in `envs/shared/ecr` (repository condivisi tra ambienti).

## secrets

- `aws_kms_key` dedicata con `enable_key_rotation = true`, `aws_kms_alias`.
- `aws_secretsmanager_secret`: `kms_key_id`, `recovery_window_in_days` (7-30; 0 mai), `name` `<progetto>/<env>/<nome>`, nessuna `aws_secretsmanager_secret_version` con `secret_string` letterale: il valore lo inserisce il DevOps fuori da Terraform. Se serve passarlo da Terraform: argomento write-only (`secret_string_wo` con `secret_string_wo_version`) da `variable` `sensitive = true` senza default, se il provider lo supporta.
- `aws_secretsmanager_secret_rotation` con Lambda di rotazione dove supportato (`rotation_rules { automatically_after_days }`).
- `aws_secretsmanager_secret_policy` con `jsonencode`: un statement per singolo ruolo (`Principal { AWS = [<arn del ruolo>] }`), mai `*` senza condizioni.
- Replica opzionale: `replica { region  kms_key_id }`.
- Output: ARN dei segreti (mai i valori). Le app li leggono a runtime con il proprio ruolo IAM.
