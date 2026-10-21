data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

# CIDR della VPC: destinazione dell'egress dell'NLB e del proxy.
data "aws_vpc" "this" {
  id = var.vpc_id
}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region
  vpc_cidr   = data.aws_vpc.this.cidr_block

  stage_name     = "api"
  alias_name     = "live"
  methods        = ["get", "put", "post", "delete", "options", "head", "patch", "trace"]
  auth_scheme    = "kynfra-authorizer"
  authorizer_key = "authorizer"
  use_lambda_jwt = var.authorizer == "lambda"

  functions = { for k, h in var.handlers : k => h if h.kind == "function" }
  services  = { for k, h in var.handlers : k => h if h.kind == "ms" }
  has_ms    = length(local.services) > 0

  # Lambda del progetto più l'authorizer OIDC (codice fuori dal kit, come le function: zip nel bucket degli artefatti)
  lambdas = merge(
    { for k, h in local.functions : k => {
      name    = "${local.name}-${replace(replace(k, "/functions/", "-"), "/", "-")}"
      runtime = h.runtime
      handler = h.handler
      context = split("/", k)[0]
      key     = "${replace(k, "/functions/", "/")}.zip"
    } },
    local.use_lambda_jwt ? { (local.authorizer_key) = {
      name    = "${local.name}-authorizer"
      runtime = var.authorizer_runtime
      handler = var.authorizer_handler
      context = ""
      key     = "authorizer/authorizer.zip"
    } } : {}
  )
  in_vpc = { for k, l in local.lambdas : k => var.has_db && k != local.authorizer_key }

  # Segreti leggibili: quelli del contesto (functions e ms) o del job, dallo stack secrets (policy identity, R34).
  lambda_secrets = { for k, l in local.lambdas : k => [for n in lookup(var.context_secrets, l.context, []) : var.secret_arns[n]] }

  ms_keys  = sort(keys(local.services))
  ms_ports = { for i, k in local.ms_keys : k => lookup(var.ms_listener_ports, k, 10001 + i) }

  # Identità dei pod (EKS Pod Identity): un ruolo per microservizio e per job, service account <contesto>-<nome> o <job>
  pods = merge(
    { for k in local.ms_keys : k => {
      service_account = replace(k, "/ms/", "-")
      secrets         = lookup(var.context_secrets, split("/", k)[0], [])
      job             = ""
    } },
    { for j in keys(var.jobs) : "jobs/${j}" => {
      service_account = j
      secrets         = lookup(var.context_secrets, j, [])
      job             = j
    } }
  )
  # un microservizio senza segreti non ha permessi AWS: ruolo senza policy
  pod_policies = { for k, p in local.pods : k => p if p.job != "" || length(p.secrets) > 0 }
  scheduled    = { for j, v in var.jobs : j => v if v.trigger == "schedule" }

  db_ports = { POSTGRESQL = 5432, MYSQL = 3306, SQLSERVER = 1433 }
  db_port  = local.db_ports[var.db_engine_family]
  # rds-db:connect si concede sul resource id del proxy (prx-…), ultimo campo dell'ARN
  db_user_arn = var.has_db ? "arn:${local.partition}:rds-db:${local.region}:${local.account_id}:dbuser:${element(split(":", aws_db_proxy.this[0].arn), 6)}/${var.db_iam_user}" : ""

  log_group_arn_prefix = "arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group"
  waf_log_group        = "aws-waf-logs-${local.name}-api"
  account_root         = "arn:${local.partition}:iam::${local.account_id}:root"
  eks_cluster_arn      = "arn:${local.partition}:eks:${local.region}:${local.account_id}:cluster/${var.eks_cluster_name}"
  noncurrent_days      = 90
  multipart_days       = 7
  log_expiration_days  = 365

  # ------------------------------------------------------------ OpenAPI -> body di API Gateway
  # Lo schema di kybes resta l'unica fonte: Terraform lo legge a ogni plan e aggiunge a ogni operazione integrazione,
  # validatore e authorizer. Un'operazione nuova appare al plan successivo (con la sua route in handlers.auto.tfvars
  # o, senza rigenerare, con x-kybes-handler verso un handler già esistente).
  openapi_doc = yamldecode(file(var.openapi_file))

  # Percorso base dell'API = percorso di servers[0].url (es. https://api.example.com/v1 -> /v1; vuoto se assente),
  # anteposto ai percorsi delle operazioni che non lo contengono già. Stage "api": l'URL diretto è
  # https://<id>.execute-api.<regione>.amazonaws.com/api/v1/... e il behavior /api/* della SPA (origin path vuoto)
  # inoltra /api/v1/... senza modifiche. Le chiavi di routes restano i percorsi dello schema.
  base_path = trimsuffix(try(regex("^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/]+)?(/[^?#]*)", local.openapi_doc.servers[0].url)[0], ""), "/")
  resource_paths = { for p in keys(local.openapi_doc.paths) : p => (
    local.base_path == "" || p == local.base_path || startswith(p, "${local.base_path}/") ? p : "${local.base_path}${p}"
  ) }

  operations = merge([
    for p, item in local.openapi_doc.paths : {
      for m, op in item : "${upper(m)} ${p}" => {
        path    = local.resource_paths[p]
        method  = upper(m)
        handler = try(var.routes["${upper(m)} ${p}"], trim(op["x-kybes-handler"], "/ "), "")
        public  = length(try(op.security, ["eredita"])) == 0
      } if contains(local.methods, m)
    }
  ]...)

  unmapped = sort([for r, o in local.operations : r if !contains(keys(var.handlers), o.handler)])
  # pubbliche solo se lo schema lo dice (security: []) e la config di kynfra le approva (public_routes)
  protected = { for r, o in local.operations : r => !(o.public && contains(var.public_routes, r)) }

  # integrazione per operazione: Lambda proxy verso l'alias live, oppure VPC link -> NLB interno -> pod del microservizio
  integrations = { for r, o in local.operations : r => jsondecode(try(var.handlers[o.handler].kind, "") == "ms" ? jsonencode({
    type                = "http_proxy"
    httpMethod          = o.method
    uri                 = "http://${try(aws_lb.ms[0].dns_name, "")}:${try(local.ms_ports[o.handler], 0)}${replace(o.path, "+}", "}")}"
    connectionType      = "VPC_LINK"
    connectionId        = try(aws_api_gateway_vpc_link.ms[0].id, "")
    passthroughBehavior = "when_no_match"
    timeoutInMillis     = 29000
    requestParameters   = { for m in regexall("\\{([A-Za-z0-9_.-]+)\\+?\\}", o.path) : "integration.request.path.${m[0]}" => "method.request.path.${m[0]}" }
    }) : jsonencode({
    type                = "aws_proxy"
    httpMethod          = "POST"
    uri                 = try(aws_lambda_alias.this[o.handler].invoke_arn, "")
    passthroughBehavior = "when_no_match"
  })) }

  security_scheme = jsondecode(local.use_lambda_jwt ? jsonencode({
    type                           = "apiKey"
    name                           = "Authorization"
    in                             = "header"
    "x-amazon-apigateway-authtype" = "custom"
    "x-amazon-apigateway-authorizer" = {
      type                         = "token"
      authorizerUri                = try(aws_lambda_alias.this[local.authorizer_key].invoke_arn, "")
      authorizerResultTtlInSeconds = 300
      identityValidationExpression = "^Bearer [-0-9A-Za-z._~+/]+=*$"
    }
    }) : jsonencode({
    type                           = "apiKey"
    name                           = "Authorization"
    in                             = "header"
    "x-amazon-apigateway-authtype" = "cognito_user_pools"
    "x-amazon-apigateway-authorizer" = {
      type         = "cognito_user_pools"
      providerARNs = [var.cognito_user_pool_arn]
    }
  }))

  paths = { for p, item in local.openapi_doc.paths : local.resource_paths[p] => merge(
    { for k, v in item : k => v if !contains(local.methods, k) },
    { for m, op in item : m => merge(op, {
      "x-amazon-apigateway-integration"       = local.integrations["${upper(m)} ${p}"]
      "x-amazon-apigateway-request-validator" = "all"
      security                                = local.protected["${upper(m)} ${p}"] ? [{ (local.auth_scheme) = [] }] : []
    }) if contains(local.methods, m) }
  ) }

  openapi = merge(local.openapi_doc, {
    paths      = local.paths
    security   = [{ (local.auth_scheme) = [] }]
    components = merge(try(local.openapi_doc.components, {}), { securitySchemes = { (local.auth_scheme) = local.security_scheme } })
    "x-amazon-apigateway-request-validators" = {
      all = { validateRequestBody = true, validateRequestParameters = true }
    }
  })
}

# ---------------------------------------------------------------- chiave KMS del backend

# Log group (Lambda, API Gateway, WAF), code SQS, variabili d'ambiente delle Lambda e bucket degli artefatti.
resource "aws_kms_key" "this" {
  description             = "Cifratura del backend ${local.name}: log, code dei job, variabili delle Lambda, artefatti"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = local.account_root }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncryption"
        Effect    = "Allow"
        Principal = { Service = "logs.${local.region}.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "${local.log_group_arn_prefix}:/aws/lambda/${local.name}-*",
              "${local.log_group_arn_prefix}:/aws/apigateway/${local.name}-*",
              "${local.log_group_arn_prefix}:API-Gateway-Execution-Logs_*",
              "${local.log_group_arn_prefix}:${local.waf_log_group}"
            ]
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "this" {
  name          = "alias/${local.name}-backend"
  target_key_id = aws_kms_key.this.key_id
}

# ---------------------------------------------------------------- bucket degli artefatti delle Lambda

# Gli zip li carica la build (CI): Terraform riferisce chiave e hash passati come variabili, non costruisce il codice.
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts-${local.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = local.noncurrent_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.multipart_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.artifacts]
}

data "aws_iam_policy_document" "artifacts" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  policy = data.aws_iam_policy_document.artifacts.json

  depends_on = [aws_s3_bucket_public_access_block.artifacts]
}

# ---------------------------------------------------------------- Lambda (una per function, più l'authorizer)

resource "aws_cloudwatch_log_group" "lambda" {
  for_each = local.lambdas

  name              = "/aws/lambda/${each.value.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_iam_role" "lambda" {
  for_each = local.lambdas

  name = each.value.name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

# Ruolo dedicato per function: log del proprio gruppo, X-Ray, chiave delle variabili, segreti del contesto (policy
# identity sugli ARN dello stack secrets) e, con schemas/db, rds-db:connect sul proxy come db_iam_user.
data "aws_iam_policy_document" "lambda" {
  for_each = local.lambdas

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda[each.key].arn}:*"]
  }

  statement {
    sid       = "XRayTracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }

  statement {
    sid       = "EnvironmentKey"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.this.arn]
  }

  dynamic "statement" {
    for_each = length(local.lambda_secrets[each.key]) > 0 ? toset(["secrets"]) : toset([])

    content {
      sid       = "ReadContextSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = local.lambda_secrets[each.key]
    }
  }

  dynamic "statement" {
    for_each = length(local.lambda_secrets[each.key]) > 0 ? toset(["secrets-key"]) : toset([])

    content {
      sid       = "DecryptContextSecrets"
      actions   = ["kms:Decrypt"]
      resources = [var.secrets_kms_key_arn]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${local.region}.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.in_vpc[each.key] ? toset(["db"]) : toset([])

    content {
      sid       = "ConnectDbProxy"
      actions   = ["rds-db:connect"]
      resources = [local.db_user_arn]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  for_each = local.lambdas

  name   = "${each.value.name}-runtime"
  role   = aws_iam_role.lambda[each.key].id
  policy = data.aws_iam_policy_document.lambda[each.key].json
}

# Interfacce di rete nella VPC (solo le Lambda con accesso al DB).
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  for_each = { for k, l in local.lambdas : k => l if local.in_vpc[k] }

  role       = aws_iam_role.lambda[each.key].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Timeout 10 s (regola di kybes: le function sincrone terminano entro 10 s; oltre si usa un microservizio). Nessun
# segreto nelle variabili d'ambiente: solo ARN, endpoint e nomi; i valori si leggono a runtime con il ruolo.
resource "aws_lambda_function" "this" {
  for_each = local.lambdas

  function_name    = each.value.name
  role             = aws_iam_role.lambda[each.key].arn
  runtime          = each.value.runtime
  handler          = each.value.handler
  s3_bucket        = aws_s3_bucket.artifacts.id
  s3_key           = lookup(var.artifact_keys, each.key, each.value.key)
  source_code_hash = lookup(var.artifact_sha256s, each.key, null)
  timeout          = 10
  memory_size      = var.lambda_memory_size
  publish          = true
  kms_key_arn      = aws_kms_key.this.arn

  tracing_config {
    mode = "Active"
  }

  logging_config {
    log_format = "JSON"
    log_group  = aws_cloudwatch_log_group.lambda[each.key].name
  }

  environment {
    variables = merge(
      { KYBES_ENVIRONMENT = var.environment, KYBES_HANDLER = each.key },
      length(local.lambda_secrets[each.key]) > 0 ? { SECRET_ARNS = jsonencode(local.lambda_secrets[each.key]) } : {},
      local.in_vpc[each.key] ? { DB_PROXY_ENDPOINT = aws_db_proxy.this[0].endpoint, DB_PORT = tostring(local.db_port), DB_USER = var.db_iam_user } : {},
      each.key == local.authorizer_key ? { OIDC_ISSUER = var.oidc_issuer, OIDC_AUDIENCE = var.oidc_audience } : {}
    )
  }

  dynamic "vpc_config" {
    for_each = local.in_vpc[each.key] ? toset(["vpc"]) : toset([])

    content {
      subnet_ids         = var.private_subnet_ids
      security_group_ids = [aws_security_group.lambda[0].id]
    }
  }

  depends_on = [aws_iam_role_policy.lambda, aws_iam_role_policy_attachment.lambda_vpc]
}

resource "aws_lambda_alias" "this" {
  for_each = local.lambdas

  name             = local.alias_name
  function_name    = aws_lambda_function.this[each.key].function_name
  function_version = aws_lambda_function.this[each.key].version
}

# Invocazione solo da questa API: lo stage api per le function, gli authorizer per la Lambda authorizer.
resource "aws_lambda_permission" "api" {
  for_each = local.lambdas

  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.this[each.key].function_name
  qualifier     = aws_lambda_alias.this[each.key].name
  principal     = "apigateway.amazonaws.com"
  source_arn    = each.key == local.authorizer_key ? "${aws_api_gateway_rest_api.this.execution_arn}/authorizers/*" : "${aws_api_gateway_rest_api.this.execution_arn}/${local.stage_name}/*/*"
}

# ---------------------------------------------------------------- API Gateway REST

resource "aws_api_gateway_rest_api" "this" {
  name        = "${local.name}-api"
  description = "API del backend ${local.name}, generata da schemas/openapi.yaml di kybes"
  body        = jsonencode(local.openapi)

  endpoint_configuration {
    types = ["REGIONAL"]
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = length(local.unmapped) == 0
      error_message = "Operazioni OpenAPI senza handler esistente: ${join(", ", local.unmapped)}. Aggiungi x-kybes-handler all'operazione (verso services/<contesto>/functions|ms/<nome>) e rigenera con /kynfra:create-backend-infra-aws."
    }
  }
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.this.id

  triggers = {
    redeployment = sha1(aws_api_gateway_rest_api.this.body)
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${local.name}-access"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

# Gruppo dei log di esecuzione creato prima dello stage, così ha retention e cifratura (altrimenti lo crea API
# Gateway senza scadenza).
resource "aws_cloudwatch_log_group" "execution" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.this.id}/${local.stage_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

# Stage api: tracing X-Ray, access log JSON con correlationId = $context.requestId. Il ruolo CloudWatch di API
# Gateway (impostazione unica per account e regione) lo imposta lo stack condiviso envs/shared/apigw-account, da
# applicare prima: senza, access log ed execution log non si scrivono.
resource "aws_api_gateway_stage" "this" {
  rest_api_id          = aws_api_gateway_rest_api.this.id
  deployment_id        = aws_api_gateway_deployment.this.id
  stage_name           = local.stage_name
  xray_tracing_enabled = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    format = jsonencode({
      correlationId      = "$context.requestId"
      extendedRequestId  = "$context.extendedRequestId"
      requestTime        = "$context.requestTime"
      sourceIp           = "$context.identity.sourceIp"
      httpMethod         = "$context.httpMethod"
      resourcePath       = "$context.resourcePath"
      status             = "$context.status"
      protocol           = "$context.protocol"
      responseLength     = "$context.responseLength"
      responseLatency    = "$context.responseLatency"
      integrationStatus  = "$context.integration.status"
      integrationLatency = "$context.integration.latency"
      principalId        = "$context.authorizer.principalId"
      errorMessage       = "$context.error.message"
      xrayTraceId        = "$context.xrayTraceId"
    })
  }

  depends_on = [aws_cloudwatch_log_group.execution]
}

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.this.id
  stage_name  = aws_api_gateway_stage.this.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled        = true
    logging_level          = "INFO"
    data_trace_enabled     = false
    throttling_rate_limit  = var.throttling_rate_limit
    throttling_burst_limit = var.throttling_burst_limit
  }
}

# ---------------------------------------------------------------- WAF (regionale, sullo stage)

resource "aws_wafv2_web_acl" "this" {
  count = var.waf_enabled ? 1 : 0

  name        = "${local.name}-api"
  description = "WAF dell'API ${local.name}: managed rule set AWS e rate limit per IP"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "aws-common"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-api-aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-api-aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 30

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-api-aws-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # Anonymous IP list: VPN, Tor e proxy anonimi bloccati; HostingProviderIPList (cloud e hosting, da cui arrivano
  # anche integrazioni server-to-server legittime) solo contato.
  rule {
    name     = "aws-anonymous-ip"
    priority = 35

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"

        rule_action_override {
          name = "HostingProviderIPList"

          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-api-aws-anonymous-ip"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "rate-limit-ip"
    priority = 40

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name}-api-rate-limit-ip"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}-api"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "this" {
  count = var.waf_enabled ? 1 : 0

  resource_arn = aws_api_gateway_stage.this.arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

resource "aws_cloudwatch_log_group" "waf" {
  count = var.waf_enabled ? 1 : 0

  name              = local.waf_log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

# Policy dedicata: evita che WAF aggiorni la policy condivisa AWSWAF-LOGS dell'account (limite di dimensione).
resource "aws_cloudwatch_log_resource_policy" "waf" {
  count = var.waf_enabled ? 1 : 0

  policy_name = "${local.name}-api-waf-logs"
  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "WafLogDelivery"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource  = "${aws_cloudwatch_log_group.waf[0].arn}:*"
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnLike      = { "aws:SourceArn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:*" }
        }
      }
    ]
  })
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = var.waf_enabled ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  depends_on = [aws_cloudwatch_log_resource_policy.waf]
}

# ---------------------------------------------------------------- bucket dei log

# Log di accesso S3 del bucket degli artefatti (prefisso s3/artifacts/) e access log dell'NLB dei microservizi
# (prefisso nlb/). SSE-S3: è l'unica cifratura di default ammessa come destinazione dei log di accesso S3.
resource "aws_s3_bucket" "logs" {
  bucket = "${local.name}-backend-logs-${local.account_id}"
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = local.log_expiration_days
    }

    noncurrent_version_expiration {
      noncurrent_days = local.noncurrent_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = local.multipart_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

data "aws_iam_policy_document" "logs" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "S3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/s3/artifacts/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.artifacts.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "NlbLogDeliveryWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/nlb/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid       = "NlbLogDeliveryAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3/artifacts/"

  depends_on = [aws_s3_bucket_policy.logs]
}

# ---------------------------------------------------------------- microservizi: VPC link -> NLB interno -> EKS

# API Gateway REST raggiunge la VPC solo tramite un VPC link verso un NLB: un NLB interno condiviso, un listener TCP
# per microservizio (porta 10001, 10002, … o ms_listener_ports) e un target group IP per microservizio, popolato dal
# TargetGroupBinding dell'AWS Load Balancer Controller (stack kubernetes-addons).
# Nessun ingress: il traffico del VPC link (PrivateLink) non passa dalle regole in ingresso
# (enforce_security_group_inbound_rules_on_private_link_traffic = "off"); uscita solo verso la VPC sulla porta dei pod.
resource "aws_security_group" "nlb" {
  count = local.has_ms ? 1 : 0

  name        = "${local.name}-ms-nlb"
  description = "NLB interno dei microservizi ${local.name}: solo traffico del VPC link, uscita verso i pod"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "nlb_pods" {
  count = local.has_ms ? 1 : 0

  security_group_id = aws_security_group.nlb[0].id
  description       = "Verso i pod dei microservizi nella VPC"
  ip_protocol       = "tcp"
  from_port         = var.ms_target_port
  to_port           = var.ms_target_port
  cidr_ipv4         = local.vpc_cidr
}

# I pod (VPC CNI) usano i security group dei nodi: ammettono la porta dei pod dal solo NLB.
resource "aws_vpc_security_group_ingress_rule" "nodes_from_nlb" {
  count = local.has_ms ? 1 : 0

  security_group_id            = var.eks_node_security_group_id
  description                  = "Pod dei microservizi ${local.name} dall'NLB del VPC link"
  ip_protocol                  = "tcp"
  from_port                    = var.ms_target_port
  to_port                      = var.ms_target_port
  referenced_security_group_id = aws_security_group.nlb[0].id
}

resource "aws_lb" "ms" {
  count = local.has_ms ? 1 : 0

  name                             = "${local.name}-ms"
  load_balancer_type               = "network"
  internal                         = true
  subnets                          = var.private_subnet_ids
  security_groups                  = [aws_security_group.nlb[0].id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = var.deletion_protection

  enforce_security_group_inbound_rules_on_private_link_traffic = "off"

  # i log di accesso dell'NLB si scrivono solo per i listener TLS: per il traffico TCP fanno fede gli access log di
  # API Gateway (correlationId) e i flow log della VPC
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "nlb"
    enabled = true
  }

  lifecycle {
    precondition {
      condition     = length(var.eks_cluster_name) > 0 && length(var.eks_node_security_group_id) > 0
      error_message = "Il progetto ha microservizi: serve lo stack kubernetes dello stesso ambiente (cluster_name e node_security_group_id)."
    }
  }

  depends_on = [aws_s3_bucket_policy.logs]
}

resource "aws_lb_target_group" "ms" {
  for_each = local.services

  # porta nel nome: cambiandola il gruppo nuovo nasce prima che il vecchio sia tolto dal listener
  name                 = "${local.name}-${substr(sha1(each.key), 0, 6)}-${var.ms_target_port}"
  vpc_id               = var.vpc_id
  target_type          = "ip"
  port                 = var.ms_target_port
  protocol             = "TCP"
  deregistration_delay = 30

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "traffic-port"
    path                = var.ms_health_path
    matcher             = "200-399"
    interval            = 15
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 3
  }

  tags = {
    KybesHandler = each.key
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "ms" {
  for_each = local.services

  load_balancer_arn = aws_lb.ms[0].arn
  port              = local.ms_ports[each.key]
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ms[each.key].arn
  }
}

resource "aws_api_gateway_vpc_link" "ms" {
  count = local.has_ms ? 1 : 0

  name        = "${local.name}-ms"
  description = "VPC link dell'API ${local.name} verso l'NLB interno dei microservizi"
  target_arns = [aws_lb.ms[0].arn]
}

# ---------------------------------------------------------------- job: code SQS con DLQ e schedule

resource "aws_sqs_queue" "dlq" {
  for_each = var.jobs

  name                              = "${local.name}-${each.key}-dlq"
  message_retention_seconds         = 1209600
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300
}

resource "aws_sqs_queue" "job" {
  for_each = var.jobs

  name                              = "${local.name}-${each.key}"
  visibility_timeout_seconds        = var.job_visibility_timeout_seconds
  message_retention_seconds         = 345600
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300

  # dopo 5 ricezioni senza cancellazione il messaggio va nella DLQ
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_redrive_allow_policy" "dlq" {
  for_each = var.jobs

  queue_url = aws_sqs_queue.dlq[each.key].id
  redrive_allow_policy = jsonencode({
    redrivePermission = "byQueue"
    sourceQueueArns   = [aws_sqs_queue.job[each.key].arn]
  })
}

# Job a calendario: EventBridge Scheduler scrive un messaggio nella coda, KEDA (scaler aws-sqs-queue con il ruolo
# dell'operatore dello stack kubernetes, code <project>-<env>-*) avvia il job.
resource "aws_iam_role" "scheduler" {
  count = length(local.scheduled) > 0 ? 1 : 0

  name = "${local.name}-jobs-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "scheduler.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  count = length(local.scheduled) > 0 ? 1 : 0

  name = "${local.name}-jobs-scheduler"
  role = aws_iam_role.scheduler[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SendToJobQueues"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = [for j in keys(local.scheduled) : aws_sqs_queue.job[j].arn]
      },
      {
        Sid      = "QueueKey"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.this.arn
      }
    ]
  })
}

resource "aws_scheduler_schedule" "job" {
  for_each = local.scheduled

  name                = "${local.name}-${each.key}"
  schedule_expression = each.value.schedule
  kms_key_arn         = aws_kms_key.this.arn

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_sqs_queue.job[each.key].arn
    role_arn = aws_iam_role.scheduler[0].arn
    input    = jsonencode({ job = each.key, source = "schedule" })

    retry_policy {
      maximum_retry_attempts       = 3
      maximum_event_age_in_seconds = 3600
    }
  }
}

# ---------------------------------------------------------------- ruoli dei pod (EKS Pod Identity)

resource "aws_iam_role" "pod" {
  for_each = local.pods

  name = "${local.name}-pod-${each.value.service_account}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "pods.eks.amazonaws.com" }
        Action    = ["sts:AssumeRole", "sts:TagSession"]
        Condition = {
          StringEquals = { "aws:SourceAccount" = local.account_id }
          ArnEquals    = { "aws:SourceArn" = local.eks_cluster_arn }
        }
      }
    ]
  })

  lifecycle {
    precondition {
      condition     = length(var.eks_cluster_name) > 0
      error_message = "Il progetto ha microservizi o job: serve lo stack kubernetes dello stesso ambiente (cluster_name)."
    }
  }
}

# Job: consumo della propria coda; microservizi e job: segreti del contesto (o del job) dallo stack secrets.
data "aws_iam_policy_document" "pod" {
  for_each = local.pod_policies

  dynamic "statement" {
    for_each = each.value.job != "" ? toset(["queue"]) : toset([])

    content {
      sid       = "ConsumeJobQueue"
      actions   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"]
      resources = [aws_sqs_queue.job[each.value.job].arn]
    }
  }

  dynamic "statement" {
    for_each = each.value.job != "" ? toset(["queue-key"]) : toset([])

    content {
      sid       = "QueueKey"
      actions   = ["kms:Decrypt"]
      resources = [aws_kms_key.this.arn]
    }
  }

  dynamic "statement" {
    for_each = length(each.value.secrets) > 0 ? toset(["secrets"]) : toset([])

    content {
      sid       = "ReadSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [for n in each.value.secrets : var.secret_arns[n]]
    }
  }

  dynamic "statement" {
    for_each = length(each.value.secrets) > 0 ? toset(["secrets-key"]) : toset([])

    content {
      sid       = "DecryptSecrets"
      actions   = ["kms:Decrypt"]
      resources = [var.secrets_kms_key_arn]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${local.region}.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role_policy" "pod" {
  for_each = local.pod_policies

  name   = "${local.name}-pod-${each.value.service_account}"
  role   = aws_iam_role.pod[each.key].id
  policy = data.aws_iam_policy_document.pod[each.key].json
}

resource "aws_eks_pod_identity_association" "pod" {
  for_each = local.pods

  cluster_name    = var.eks_cluster_name
  namespace       = var.kubernetes_namespace
  service_account = each.value.service_account
  role_arn        = aws_iam_role.pod[each.key].arn
}

# ---------------------------------------------------------------- RDS Proxy (con schemas/db)

# Il database è fuori dalla v1: un'istanza esistente con l'autenticazione IAM attiva
# (iam_database_authentication_enabled = true sull'istanza: la data source non la espone). IAM end-to-end
# (default_auth_scheme = "IAM_AUTH"): le Lambda si collegano al proxy con un token IAM come db_iam_user e il proxy
# si collega al database con il proprio ruolo come lo stesso utente (GRANT rds_iam), senza segreti.
data "aws_db_instance" "this" {
  count = var.has_db ? 1 : 0

  db_instance_identifier = var.db_instance_identifier
}

resource "aws_security_group" "lambda" {
  count = var.has_db ? 1 : 0

  name        = "${local.name}-lambda"
  description = "Lambda del backend ${local.name}: uscita verso RDS Proxy e i servizi AWS (443)"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_egress_rule" "lambda_proxy" {
  count = var.has_db ? 1 : 0

  security_group_id            = aws_security_group.lambda[0].id
  description                  = "Verso RDS Proxy"
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
  referenced_security_group_id = aws_security_group.proxy[0].id
}

resource "aws_vpc_security_group_egress_rule" "lambda_https" {
  count = var.has_db ? 1 : 0

  security_group_id = aws_security_group.lambda[0].id
  description       = "HTTPS verso i servizi AWS (endpoint VPC o NAT)"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "proxy" {
  count = var.has_db ? 1 : 0

  name        = "${local.name}-db-proxy"
  description = "RDS Proxy del backend ${local.name}: ingresso dal solo security group delle Lambda"
  vpc_id      = var.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "proxy_from_lambda" {
  count = var.has_db ? 1 : 0

  security_group_id            = aws_security_group.proxy[0].id
  description                  = "Dalle Lambda del backend"
  ip_protocol                  = "tcp"
  from_port                    = local.db_port
  to_port                      = local.db_port
  referenced_security_group_id = aws_security_group.lambda[0].id
}

resource "aws_vpc_security_group_egress_rule" "proxy_db" {
  count = var.has_db ? 1 : 0

  security_group_id = aws_security_group.proxy[0].id
  description       = "Verso il database nella VPC"
  ip_protocol       = "tcp"
  from_port         = local.db_port
  to_port           = local.db_port
  cidr_ipv4         = local.vpc_cidr
}

resource "aws_iam_role" "proxy" {
  count = var.has_db ? 1 : 0

  name = "${local.name}-db-proxy"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "rds.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

resource "aws_iam_role_policy" "proxy" {
  count = var.has_db ? 1 : 0

  name = "${local.name}-db-proxy"
  role = aws_iam_role.proxy[0].id
  # il proxy si collega al database come db_iam_user con il proprio ruolo (resource id dbi-… dell'istanza)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ConnectDatabase"
        Effect   = "Allow"
        Action   = "rds-db:connect"
        Resource = "arn:${local.partition}:rds-db:${local.region}:${local.account_id}:dbuser:${data.aws_db_instance.this[0].resource_id}/${var.db_iam_user}"
      }
    ]
  })
}

resource "aws_db_proxy" "this" {
  count = var.has_db ? 1 : 0

  name                   = "${local.name}-db"
  engine_family          = var.db_engine_family
  default_auth_scheme    = "IAM_AUTH"
  require_tls            = true
  idle_client_timeout    = 1800
  debug_logging          = false
  role_arn               = aws_iam_role.proxy[0].arn
  vpc_security_group_ids = [aws_security_group.proxy[0].id]
  vpc_subnet_ids         = var.private_subnet_ids

  depends_on = [aws_iam_role_policy.proxy]
}

resource "aws_db_proxy_default_target_group" "this" {
  count = var.has_db ? 1 : 0

  db_proxy_name = aws_db_proxy.this[0].name

  connection_pool_config {
    connection_borrow_timeout    = 120
    max_connections_percent      = 90
    max_idle_connections_percent = 50
  }
}

resource "aws_db_proxy_target" "this" {
  count = var.has_db ? 1 : 0

  db_proxy_name          = aws_db_proxy.this[0].name
  target_group_name      = aws_db_proxy_default_target_group.this[0].name
  db_instance_identifier = var.db_instance_identifier
}
