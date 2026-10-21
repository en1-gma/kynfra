# Module `spa`

Static hosting for a single-page application: a private S3 bucket served only by CloudFront.

| Area | What the module creates |
|---|---|
| Content | `<project>-<env>-site-<account>` bucket: BucketOwnerEnforced, public access block (4 flags), versioning, SSE-S3, lifecycle on noncurrent versions, server access logs, TLS-only policy; `s3:GetObject` and `s3:ListBucket` (missing objects return 404, not 403) only for `cloudfront.amazonaws.com` with `AWS:SourceArn` = the distribution (OAC, never OAI or the website endpoint). |
| TLS | ACM certificate in `us-east-1` (provider `aws.us_east_1`) validated through DNS records in `zone_id`; viewer certificate `sni-only`, `TLSv1.2_2021`; HTTP redirected to HTTPS. |
| DNS | Route53 alias records A and AAAA for `domain_name`. |
| Routing | CloudFront Function (`cloudfront-js-2.0`, viewer-request) rewriting extensionless paths to `/index.html`, `/api/*` excluded. No `custom_error_response` mapping 403/404 to `index.html`, so real errors (including API errors) stay visible. Limit: a route whose last segment contains a dot (e.g. `/users/john.doe`) is treated as a file and returns 404; use routes without dots in the last segment or adapt the function. |
| Headers | Response headers policy: HSTS (2 years, includeSubDomains, preload), CSP (`content_security_policy`, strict default), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`. |
| Cache | Default behavior honours the object `Cache-Control` (default TTL 0); `/index.html` never cached (managed CachingDisabled); `/assets/*` and `/_app/immutable/*` with managed CachingOptimized. |
| Logs | CloudFront standard logs v2 (delivery source/destination/delivery in `us-east-1`) to the private `<project>-<env>-cdn-logs-<account>` bucket under the explicit `cloudfront/` prefix (365-day expiration); `project` + `environment` are validated so this name fits in 63 characters. |
| WAF | With `waf_enabled` (mandatory in prod): CLOUDFRONT web ACL in `us-east-1` with AWSManagedRulesCommonRuleSet, KnownBadInputs, AmazonIpReputationList and a per-IP rate limit (`waf_rate_limit`); logs to a KMS-encrypted log group (`aws-waf-logs-*`, 365 days). |
| API | With `api_domain_name` set: second origin (HTTPS only, TLSv1.2) and `/api/*` behavior with CachingDisabled and AllViewerExceptHostHeader; `api_origin_path` is prepended to the forwarded path (empty for the kynfra `backend` stack, whose stage is `api`: `/api/v1/...` reaches the API unchanged). |

The caller passes both providers: `providers = { aws = aws, aws.us_east_1 = aws.us_east_1 }`.

Outputs: `bucket_name`, `distribution_id`, `distribution_domain_name` (used by the frontend deploy: upload the build with long `Cache-Control` on hashed assets and `no-cache` on `index.html`, then invalidate `/index.html`).

The `spa` stack resolves `zone_id` from `hosted_zone` (`create` reads the `envs/shared/dns` stack, `existing:<zone_id>` uses an existing zone), checks at plan time that the zone is public and that `domain_name` is the zone name or a subdomain of it and, with `api_origin = "backend"`, reads `api_domain_name` and `api_origin_path` from the backend stack of the same environment.
