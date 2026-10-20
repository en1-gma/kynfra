# Module `elb`

Load balancer in front of the workloads: an Application Load Balancer (`type = "alb"`, default) or a Network Load Balancer (`type = "nlb"`).

| Area | What the module creates |
|---|---|
| Load balancer | `<project>-<env>-<type>` in `subnet_ids` (public, or private with `internal = true`), `drop_invalid_header_fields = true` and `desync_mitigation_mode = "strictest"` (ALB), cross-zone balancing (NLB), `enable_deletion_protection = var.deletion_protection` (mandatory in prod). |
| Listeners | ALB: 443 `HTTPS` with `ELBSecurityPolicy-TLS13-1-2-2021-06` and default action fixed-response 404; listener rule (priority 100) forwarding `Host = domain_name` to the default target group, so requests by IP or by the `*.elb.amazonaws.com` name get 404; 80 `HTTP` with only a 301 redirect to HTTPS. NLB: 443 `TLS` with the same policy, ALPN `HTTP2Preferred`, forward to the target group (no port 80). |
| TLS and DNS | Regional ACM certificate for `domain_name`, DNS-validated in `zone_id`; Route53 alias record A (and AAAA with `ip_address_type = "dualstack"`). |
| Targets | One default target group `<project>-<env>-<type>-<port>`: `target_type = "ip"` (AWS Load Balancer Controller `TargetGroupBinding` on EKS, ECS services), protocol HTTP (ALB) or TCP (NLB) on `target_port`, HTTP health check on `health_path` (200-399). Type and port are part of the name, with `create_before_destroy`, so changing them never detaches the listener. |
| Security group | `allow_from = "internet"`: 443 (and 80 for the ALB redirect) from `0.0.0.0/0` (and `::/0` with dualstack); `allow_from = "cloudfront"`: only 443 from the managed prefix list `com.amazonaws.global.cloudfront.origin-facing`; `internal = true`: 443/80 from the VPC CIDR. Egress only to the VPC CIDR on `target_port`. Every rule is an explicit `aws_vpc_security_group_*_rule` with a literal CIDR or the prefix list. |
| Access logs | Private `<project>-<env>-lb-logs-<account>` bucket (BucketOwnerEnforced, public access block, versioning, SSE-S3 as required by ALB access logs, 365-day expiration, TLS-only policy). Writes allowed only under `<type>/AWSLogs/<account>/`: ALB through the `logdelivery.elasticloadbalancing.amazonaws.com` service principal plus, in the Regions opened before December 2021 (`legacy_elb_regions`, e.g. `eu-south-1`), the regional ELB account from `aws_elb_service_account`; NLB through `delivery.logs.amazonaws.com` with source account/ARN conditions. |
| WAF | With `waf_enabled` (mandatory in prod for the ALB, rejected for the NLB): REGIONAL web ACL associated with the ALB, AWSManagedRulesCommonRuleSet, KnownBadInputs, AmazonIpReputationList and a per-IP rate limit (`waf_rate_limit`); logs to a KMS-encrypted log group (`aws-waf-logs-*`, 365 days). |

Inputs: `project`, `environment`, `type`, `internal`, `vpc_id`, `subnet_ids`, `allow_from`, `domain_name`, `zone_id`, `ip_address_type`, `target_port`, `health_path`, `deletion_protection`, `waf_enabled`, `waf_rate_limit`, `legacy_elb_regions`. `project` + `environment` are validated to fit the 32-character target group name.

Outputs: `lb_arn`, `lb_dns_name`, `lb_zone_id`, `https_listener_arn`, `target_group_arn`, `security_group_id` (allow `target_port` from it in the targets' security group).

More services on the same ALB: add an `aws_lb_target_group` and an `aws_lb_listener_rule` on `aws_lb_listener.https` (host or path condition, a priority other than 100) and, for another domain, an `aws_lb_listener_certificate`. Never attach rules to the HTTP listener.

The `elb` stack reads `vpc_id`, `public_subnet_ids` and `private_subnet_ids` from the `network` stack of the same environment (`terraform_remote_state`, key `<project>/<env>/network.tfstate`), resolves `zone_id` from `hosted_zone` (`create` reads `envs/shared/dns`, `existing:<zone_id>` uses an existing zone) and checks at plan time that the zone is public and contains `domain_name`.
