data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name          = "${var.project}-${var.environment}"
  azs           = slice(data.aws_availability_zones.available.names, 0, var.az_count)
  az_index      = { for i, az in local.azs : tostring(i) => az }
  internet      = "0.0.0.0/0"
  https_port    = 443
  subnet_bits   = 4 # /16 -> /20
  public_base   = 0
  private_base  = 4
  isolated_base = 8

  # Con nat_per_az ogni zona usa il proprio NAT, altrimenti tutte usano il NAT della prima zona.
  nat_keys   = var.nat_per_az ? keys(local.az_index) : ["0"]
  nat_for_az = { for k in keys(local.az_index) : k => var.nat_per_az ? k : "0" }

  interface_endpoints = toset(["ecr.api", "ecr.dkr", "secretsmanager", "sts", "logs"])
  service_prefix      = "com.amazonaws.${data.aws_region.current.region}"

  flow_log_group = "/aws/vpc/${local.name}/flow-logs"
  flow_log_arn   = "arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:log-group:${local.flow_log_group}"
  account_root   = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
}

# ---------------------------------------------------------------- VPC

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = local.name
  }
}

# Il security group di default non ha regole: nessun traffico, nemmeno tra le risorse che lo ereditano per errore.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-default"
  }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = local.name
  }
}

# ---------------------------------------------------------------- subnet

resource "aws_subnet" "public" {
  for_each = local.az_index

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, local.subnet_bits, local.public_base + tonumber(each.key))
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name}-public-${each.value}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  for_each = local.az_index

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, local.subnet_bits, local.private_base + tonumber(each.key))
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name}-private-${each.value}"
    Tier = "private"
  }
}

resource "aws_subnet" "isolated" {
  for_each = local.az_index

  vpc_id                  = aws_vpc.this.id
  availability_zone       = each.value
  cidr_block              = cidrsubnet(var.vpc_cidr, local.subnet_bits, local.isolated_base + tonumber(each.key))
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name}-isolated-${each.value}"
    Tier = "isolated"
  }
}

# ---------------------------------------------------------------- NAT

resource "aws_eip" "nat" {
  for_each = toset(local.nat_keys)

  domain = "vpc"

  tags = {
    Name = "${local.name}-nat-${local.az_index[each.key]}"
  }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_nat_gateway" "this" {
  for_each = toset(local.nat_keys)

  allocation_id = aws_eip.nat[each.key].id
  subnet_id     = aws_subnet.public[each.key].id

  tags = {
    Name = "${local.name}-${local.az_index[each.key]}"
  }

  depends_on = [aws_internet_gateway.this]
}

# ---------------------------------------------------------------- routing

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-public"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = local.internet
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  for_each = local.az_index

  subnet_id      = aws_subnet.public[each.key].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  for_each = local.az_index

  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-private-${each.value}"
  }
}

resource "aws_route" "private_nat" {
  for_each = local.az_index

  route_table_id         = aws_route_table.private[each.key].id
  destination_cidr_block = local.internet
  nat_gateway_id         = aws_nat_gateway.this[local.nat_for_az[each.key]].id
}

resource "aws_route_table_association" "private" {
  for_each = local.az_index

  subnet_id      = aws_subnet.private[each.key].id
  route_table_id = aws_route_table.private[each.key].id
}

# Le subnet isolate non hanno rotte verso internet: raggiungono solo la VPC e il gateway endpoint S3.
resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.this.id

  tags = {
    Name = "${local.name}-isolated"
  }
}

resource "aws_route_table_association" "isolated" {
  for_each = local.az_index

  subnet_id      = aws_subnet.isolated[each.key].id
  route_table_id = aws_route_table.isolated.id
}

# ---------------------------------------------------------------- endpoint VPC

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "${local.service_prefix}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat([for k in sort(keys(aws_route_table.private)) : aws_route_table.private[k].id], [aws_route_table.isolated.id])

  tags = {
    Name = "${local.name}-s3"
  }
}

resource "aws_security_group" "endpoints" {
  name        = "${local.name}-vpc-endpoints"
  description = "Endpoint VPC interface: HTTPS dalla VPC"
  vpc_id      = aws_vpc.this.id

  tags = {
    Name = "${local.name}-vpc-endpoints"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS dalla VPC"
  cidr_ipv4         = aws_vpc.this.cidr_block
  ip_protocol       = "tcp"
  from_port         = local.https_port
  to_port           = local.https_port
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.this.id
  service_name        = "${local.service_prefix}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [for k in sort(keys(aws_subnet.private)) : aws_subnet.private[k].id]
  security_group_ids  = [aws_security_group.endpoints.id]

  tags = {
    Name = "${local.name}-${each.key}"
  }
}

# ---------------------------------------------------------------- flow log

resource "aws_kms_key" "flow_logs" {
  description             = "Cifratura dei flow log della VPC ${local.name}"
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
        Principal = { Service = "logs.${data.aws_region.current.region}.amazonaws.com" }
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
            "kms:EncryptionContext:aws:logs:arn" = local.flow_log_arn
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "flow_logs" {
  name          = "alias/${local.name}-flow-logs"
  target_key_id = aws_kms_key.flow_logs.key_id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = local.flow_log_group
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = aws_kms_key.flow_logs.arn
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name}-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "vpc-flow-logs.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "${local.name}-flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "this" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  tags = {
    Name = local.name
  }
}
