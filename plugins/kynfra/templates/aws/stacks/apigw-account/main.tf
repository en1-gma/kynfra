data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# Ruolo CloudWatch di API Gateway: impostazione unica per account e regione (singleton), condivisa da tutti gli stack
# backend dell'account. Vive in envs/shared/apigw-account e si applica una sola volta, prima degli stack backend:
# senza, gli stage con access log o execution log non si creano.
resource "aws_iam_role" "api_gateway_logs" {
  name = "${var.project}-apigateway-cloudwatch"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "apigateway.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_gateway_logs" {
  role       = aws_iam_role.api_gateway_logs.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

# Con il provider 6 il destroy riporta sempre le impostazioni dell'account al default (reset_on_delete non esiste più).
resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.api_gateway_logs.arn

  depends_on = [aws_iam_role_policy_attachment.api_gateway_logs]
}
