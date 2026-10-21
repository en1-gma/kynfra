output "cloudwatch_role_arn" {
  description = "Ruolo CloudWatch di API Gateway impostato a livello di account e regione."
  value       = aws_api_gateway_account.this.cloudwatch_role_arn
}
