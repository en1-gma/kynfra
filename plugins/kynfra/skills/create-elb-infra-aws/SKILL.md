---
name: create-elb-infra-aws
description: Generate an AWS load balancer with kynfra (ALB, or NLB on request, in the subnets of the network stack; HTTPS/TLS listener with ELBSecurityPolicy-TLS13-1-2-2021-06 and a DNS-validated regional ACM certificate, 80 to 443 redirect, drop_invalid_header_fields, Route53 alias, access logs to a dedicated bucket, regional WAF and deletion protection in prod, IP target group with health check, security group open to the world or only to CloudFront) as an elb stack per environment. Use when the user runs /kynfra:create-elb-infra-aws or asks for an ALB, NLB or load balancer on AWS.
---

# Creare un load balancer su AWS (pattern `elb`)

Genera il modulo `modules/elb`, lo stack `envs/<env>/elb` per l'ambiente richiesto e, con `hosted_zone=create`, lo stack condiviso `envs/shared/dns` (la stessa zona del pattern `spa`). Prima di scrivere o modificare codice carica le regole della skill `kynfra-architecture` (`SKILL.md` e `references/aws.md`, sezione `elb`). Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

1. **Leggi lo stato**: `.kynfra/config.json` (`infra_root`, `project`, `region`, `environments`, `accounts`, `tags`, `iac`) e cosa esiste già sotto `infra_root`: `envs/*/elb`, `envs/*/network`, `envs/shared/dns`, `bootstrap/`, i `tfvars` esistenti. Il pattern richiede `network`: se `envs/<env>/network` manca, proponi di generarlo prima con `/kynfra:create-network-infra-aws` (lo stack elb legge `vpc_id`, `public_subnet_ids` e `private_subnet_ids` dal suo stato). Se `bootstrap/` manca, segnala che il backend S3 dello stato deve esistere prima dell'`init` degli stack e proponi `generate.py --pattern bootstrap`. Se `envs/shared/dns` esiste già (creata dalla SPA), proponi `hosted_zone=create` per riusarla.
2. **Un solo giro di domande**, solo su ciò che manca:
   - ambiente da generare (un comando per ambiente, ognuno col proprio dominio);
   - `type`: `alb` (default; HTTP/HTTPS, WAF, regole per host) oppure `nlb` (TLS terminato sul load balancer e inoltro TCP; niente WAF né porta 80);
   - `internal`: `false` (default, subnet pubbliche) oppure `true` (subnet private, client solo dalla VPC, es. dietro un VPC link di API Gateway);
   - `allow_from` per un load balancer pubblico: `internet` (443 e 80 dal mondo) oppure `cloudfront` (solo 443 dalla prefix list gestita `com.amazonaws.global.cloudfront.origin-facing`; con `internal=true` non è ammesso);
   - `domain_name` (obbligatorio), es. `api.example.com` in prod e `dev.api.example.com` in dev;
   - `hosted_zone` (obbligatorio): `existing:<zone_id>` (zona Route53 pubblica già nell'account; puoi leggerla con `aws route53 list-hosted-zones`) oppure `create` (zona di `envs/shared/dns`, riusata se esiste); con `create` e zona non ancora generata, `zone_name` (di solito il dominio radice);
   - `target_port` (default `8080`) e `health_path` (default `/healthz`) del gruppo di destinazione di default;
   - `waf_enabled` (default `true` in prod per l'ALB, obbligatorio; `false` altrove per il costo fisso; con `type=nlb` sempre `false`, anche in prod) e `deletion_protection` (default `true` in prod, obbligatoria).
   Gli ambienti e la zona già generati non vengono sovrascritti.
3. **Genera**, un comando per ambiente:

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern elb --provider aws --env prod --var domain_name=api.example.com --var hosted_zone=create --var zone_name=example.com [--var allow_from=cloudfront] [--var target_port=8080] [--var health_path=/healthz]
   python3 -B <kit>/scripts/generate.py --pattern elb --provider aws --env dev --var domain_name=dev.api.example.com --var hosted_zone=existing:Z0123456789ABCDEFGHIJ [--var type=nlb --var internal=true]
   ```

   Con `type=nlb` in prod aggiungi `--var waf_enabled=false` (il modulo rifiuta WAF su un NLB). Con più account negli ambienti e `hosted_zone=create` aggiungi `--var account=<nome>`. Il generatore non sovrascrive file esistenti salvo `--force`, che chiede l'utente. Per vedere le differenze con una versione più recente del kit: `--upgrade`.
4. **Personalizzazioni** solo con gli strumenti di modifica dei file, mai con redirect o `sed -i` da shell: ogni scrittura passa dalle regole. Il generatore crea un solo gruppo di destinazione (`target_type = "ip"`, adatto ad AWS Load Balancer Controller con `TargetGroupBinding` su EKS e ai servizi ECS). Per altri servizi sullo stesso ALB aggiungi nel modulo un `aws_lb_target_group` e un `aws_lb_listener_rule` sul listener `aws_lb_listener.https` (condizione `host_header` o `path_pattern`, priorità diversa da 100), più un certificato con `aws_lb_listener_certificate` per un altro dominio; mai regole sul listener HTTP, che fa solo redirect. Altri valori nel blocco `module "elb"` dello stack: `waf_rate_limit`, `ip_address_type = "dualstack"` (solo con subnet IPv6, che il pattern network non crea). Mantieni `ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"`, `drop_invalid_header_fields = true`, gli `access_logs` attivi, `enable_deletion_protection = var.deletion_protection` e gli ingress come regole esplicite con CIDR o prefix list letterali.
5. **Controlla**: `python3 -B <kit>/scripts/arch_check.py . --external` e correggi la causa di ogni finding (mai soppressioni inline). Se mancano strumenti esterni proponi `/kynfra:kynfra-tools`.
6. **Riepiloga** in poche righe:
   - file creati (modulo, stack dell'ambiente, eventuale `envs/shared/dns`) e output dello stack: `lb_arn`, `lb_dns_name`, `lb_zone_id`, `https_listener_arn`, `target_group_arn`, `security_group_id`;
   - costi: ore e LCU/NLCU del load balancer, WAF (web ACL, regole e richieste) dove attivo, S3 dei log;
   - comandi che esegue il DevOps con le sue credenziali (tu non li lanci): prima lo stack network dell'ambiente; con `create` e zona nuova `cd <infra_root>/envs/shared/dns && terraform init && terraform plan -out=dns.tfplan && terraform apply dns.tfplan`; poi `cd <infra_root>/envs/<env>/elb && terraform init && terraform plan -out=elb.tfplan && terraform apply elb.tfplan` (o `tofu`);
   - passi manuali: delegare i `name_servers` di una zona nuova prima dell'apply (altrimenti la validazione ACM non termina); registrare i target nel gruppo `target_group_arn` e ammettere nel security group dei target la porta `target_port` dal security group `security_group_id`; un ALB pubblico inoltra solo le richieste con Host uguale a `domain_name` (le altre ricevono 404), quindi con `allow_from=cloudfront` la distribuzione deve avere come origin `domain_name` in HTTPS senza inoltrare l'Host del viewer (origin request policy senza Host, es. `Managed-AllViewerExceptHostHeader`), e un API Gateway pubblico davanti deve chiamare `https://<domain_name>`; un ALB interno (es. dietro un VPC link di API Gateway, che manda il proprio Host) inoltra tutto al target group; con la deletion protection attiva un destroy richiede prima `deletion_protection = false` e un apply.
