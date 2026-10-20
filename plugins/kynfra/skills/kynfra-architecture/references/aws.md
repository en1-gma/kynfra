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
- `aws_cloudfront_distribution`: origin `domain_name = <bucket>.bucket_regional_domain_name` con `origin_access_control_id` (mai `s3_origin_config`, mai endpoint website); `default_cache_behavior { viewer_protocol_policy = "redirect-to-https"  response_headers_policy_id = ...  cache_policy_id = ...  function_association { event_type = "viewer-request" ... } }`; `viewer_certificate { acm_certificate_arn = ...  ssl_support_method = "sni-only"  minimum_protocol_version = "TLSv1.2_2021" }`; log di accesso v2 (`aws_cloudwatch_log_delivery_source` con `resource_arn = <distribuzione>.arn`, `aws_cloudwatch_log_delivery_destination` verso il bucket dei log, `aws_cloudwatch_log_delivery`, provider `us_east_1`; il `logging_config` legacy richiede ACL e non consegna nelle regioni opt-in come `eu-south-1`); `web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.<nome>[0].arn : null`; `aliases`, `default_root_object = "index.html"`. Nessun `custom_error_response` 403/404 che maschera le API.
- `aws_cloudfront_function` (`runtime = "cloudfront-js-2.0"`, `publish = true`): riscrive in `/index.html` le richieste senza estensione.
- `aws_cloudfront_response_headers_policy`: `strict_transport_security` (HSTS), `content_security_policy`, `content_type_options { override = true }`, `frame_options` o `frame-ancestors`.
- `aws_cloudfront_cache_policy`: asset immutabili a lungo (gestita `Managed-CachingOptimized` sui percorsi con hash), `index.html` senza cache (`Managed-CachingDisabled`); il default behavior rispetta il `Cache-Control` dell'oggetto con `default_ttl = 0`, perché la scelta del behavior avviene prima della riscrittura della CloudFront Function.
- Bucket dei log: privato con le cinque risorse delle fondamenta e `BucketOwnerEnforced` (i log v2 non usano ACL), SSE-S3, policy per `delivery.logs.amazonaws.com` (`s3:GetBucketAcl` e `s3:ListBucket` sul bucket, `s3:PutObject` sul solo prefisso) con `aws:SourceAccount` e `aws:SourceArn`. Prefisso esplicito nella destinazione (`destination_resource_arn = "${<bucket>.arn}/cloudfront"`): per CloudFront sostituisce il default `AWSLogs/<account>/CloudFront/`.
- Policy del bucket della SPA: `s3:GetObject` sugli oggetti e `s3:ListBucket` sul bucket per `cloudfront.amazonaws.com` (stessa condizione `AWS:SourceArn`), così un oggetto mancante dà 404 e non 403.
- Quota: al massimo 10 `aws_cloudwatch_log_resource_policy` per regione e account. Il pattern ne crea una per ambiente con WAF (log WAF) e una per la zona condivisa (log delle query), tutte in `us-east-1`: con molti ambienti o progetti nello stesso account accorpale in una sola policy.
- `aws_acm_certificate` (provider `us_east_1`, `validation_method = "DNS"`), `aws_route53_record` di validazione, `aws_acm_certificate_validation`.
- `aws_route53_record` alias A e AAAA verso la distribuzione.
- WAF: `aws_wafv2_web_acl` con `scope = "CLOUDFRONT"` (provider `us_east_1`), managed rule group `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesAmazonIpReputationList` e una regola `rate_based_statement`; attivo in prod via `waf_enabled`; log su un log group `aws-waf-logs-*` in `us-east-1` con retention e KMS.
- Zona: `hosted_zone = existing:<zone_id>` o `create` (stack `envs/shared/dns` con `zone_name`, letto con `terraform_remote_state` dalla chiave `<progetto>/shared/dns.tfstate`); lo stack spa legge la zona con `data "aws_route53_zone"` e con `postcondition` verifica che sia pubblica e che `domain_name` sia la zona o un suo sottodominio. Un comando per ambiente (`single_env`), ognuno col proprio dominio.
- Opzionale `/api/*` (`api_origin = backend`): secondo origin (output `api_domain_name` e `api_origin_path` dello stack backend via `terraform_remote_state`, `origin_protocol_policy = "https-only"`, `origin_ssl_protocols = ["TLSv1.2"]`) e `ordered_cache_behavior` con `https-only` o `redirect-to-https`, `Managed-CachingDisabled` e `Managed-AllViewerExceptHostHeader`.

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

- `aws_lb` unico con `load_balancer_type` da `var.type` (`alb` → `application`, `nlb` → `network`), `drop_invalid_header_fields = true` (letterale; il provider lo ignora sull'NLB), `desync_mitigation_mode = "strictest"` sull'ALB, `enable_deletion_protection = var.deletion_protection` con `true` nei tfvars di prod, `access_logs { bucket = ...  prefix = ...  enabled = true }`, `internal` da variabile (subnet private) o pubblico (subnet pubbliche), `security_groups` anche sull'NLB.
- `aws_lb_listener` 80 (solo ALB): `protocol = "HTTP"` letterale e `default_action { type = "redirect" redirect { protocol = "HTTPS" port = "443" status_code = "HTTP_301" } }`; nessuna `aws_lb_listener_rule` sul listener HTTP.
- `aws_lb_listener` 443: `protocol = "HTTPS"` (ALB) o `"TLS"` (NLB, `alpn_policy`) letterali, in risorse separate con `count`; `ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"`, `certificate_arn = aws_acm_certificate_validation.<nome>.certificate_arn` (ACM regionale, validazione DNS). ALB: default `fixed-response` 404 e `aws_lb_listener_rule` con `host_header = [domain_name]` verso il target group.
- `aws_lb_target_group` con `target_type = "ip"` (EKS con TargetGroupBinding, ECS), `health_check { path  matcher  healthy_threshold  unhealthy_threshold }`, nome con tipo e porta e `create_before_destroy`.
- Security group con regole esplicite `aws_vpc_security_group_ingress_rule` (CIDR letterali `0.0.0.0/0`/`::/0` solo su 443 e 80, o `prefix_list_id` della data `aws_ec2_managed_prefix_list` `com.amazonaws.global.cloudfront.origin-facing` solo su 443, o il CIDR della VPC per i load balancer interni) e `aws_vpc_security_group_egress_rule` solo verso il CIDR della VPC sulla porta dei target; niente `for_each` su variabili negli ingress.
- Bucket dei log: privato, versionato, SSE-S3 (`AES256`, l'unica ammessa dagli access log dell'ALB), policy TLS only in `data "aws_iam_policy_document"` con `dynamic "statement"`: ALB con il service principal `logdelivery.elasticloadbalancing.amazonaws.com` più, nelle regioni aperte prima di dicembre 2021 (variabile `legacy_elb_regions`, es. `eu-south-1`), l'account ELB della regione da `data "aws_elb_service_account"` (con `count`); NLB con `delivery.logs.amazonaws.com` e condition `aws:SourceAccount`/`aws:SourceArn`. Le regioni nei moduli vanno in variabili (regola `region-pinning`).
- WAF: `aws_wafv2_web_acl` con `scope = "REGIONAL"` + `aws_wafv2_web_acl_association`, attivo in prod per l'ALB (l'NLB non supporta WAF), log su log group `aws-waf-logs-*` cifrato con KMS.
- Dipendenze: `network` (`vpc_id`, `public_subnet_ids`, `private_subnet_ids`) via `terraform_remote_state` sulla chiave `<progetto>/<env>/network.tfstate`; zona come per `spa` (`create` → `envs/shared/dns`, `existing:<zone_id>`) con `data "aws_route53_zone"` e `postcondition`. Un comando per ambiente (`single_env`).

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
