---
name: create-spa-infra-aws
description: Generate AWS hosting for a single-page application with kynfra (private S3 bucket behind CloudFront with OAC, ACM certificate in us-east-1, Route53 alias records, client-side routing via CloudFront Function, security headers, access logs, WAF in prod, optional /api/* to the backend API Gateway) as a spa stack per environment, plus a shared DNS zone when requested. Use when the user runs /kynfra:create-spa-infra-aws or asks to host a SPA/frontend/static site on AWS.
---

# Creare l'hosting di una SPA su AWS (pattern `spa`)

Genera il modulo `modules/spa`, lo stack `envs/<env>/spa` per ogni ambiente richiesto e, con `hosted_zone=create`, lo stack condiviso `envs/shared/dns` (zona Route53 pubblica). Prima di scrivere o modificare codice carica le regole della skill `kynfra-architecture` (`SKILL.md` e `references/aws.md`, sezione `spa`). Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

1. **Leggi lo stato**: `.kynfra/config.json` (`infra_root`, `project`, `region`, `environments`, `accounts`, `tags`, `iac`) e cosa esiste già sotto `infra_root`: `envs/*/spa`, `envs/shared/dns`, `envs/*/backend`, `bootstrap/`, i `tfvars` esistenti. Se `bootstrap/` manca, segnala che il backend S3 dello stato deve esistere prima dell'`init` degli stack e proponi di generarlo (`generate.py --pattern bootstrap`). Il pattern `spa` non ha `requires`; se l'utente vuole `/api/*` e `envs/<env>/backend` non esiste, proponi `/kynfra:create-backend-infra-aws` (lo stack spa legge i suoi output).
2. **Un solo giro di domande**, solo su ciò che manca:
   - ambienti da generare (default: tutti quelli in config);
   - `domain_name` (obbligatorio): dominio pubblico della SPA per ambiente, es. `app.example.com` in prod e `dev.app.example.com` in dev;
   - `hosted_zone` (obbligatorio): `existing:<zone_id>` se la zona Route53 pubblica esiste già nell'account (puoi leggerla con `aws route53 list-hosted-zones`), oppure `create` per crearla in `envs/shared/dns`;
   - `zone_name` (con `create`): nome della zona, di solito il dominio radice (es. `example.com`); se vuoto la zona prende il `domain_name` del primo comando che la genera. Ogni `domain_name` deve essere il nome della zona o un suo sottodominio: lo stack spa lo verifica al plan;
   - `api_origin`: `backend` per servire `/api/*` dall'API Gateway dello stack backend dello stesso ambiente (stesso dominio, niente CORS), vuoto altrimenti;
   - `waf_enabled` (default `true` in prod, obbligatorio; `false` altrove: il WAF ha un costo fisso mensile).
   Gli ambienti e la zona già generati non vengono sovrascritti.
3. **Genera**, un comando per ambiente, ognuno con il proprio `domain_name` (il generatore rifiuta più ambienti nello stesso comando: lo stesso dominio in due distribuzioni collide su alias e record):

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern spa --provider aws --env prod --var domain_name=app.example.com --var hosted_zone=create --var zone_name=example.com [--var api_origin=backend]
   python3 -B <kit>/scripts/generate.py --pattern spa --provider aws --env dev --var domain_name=dev.app.example.com --var hosted_zone=create [--var api_origin=backend] [--var waf_enabled=true]
   ```

   `envs/shared/dns` si genera solo al primo comando con `create`; nei successivi resta com'è (file saltati). Con più account negli ambienti e `hosted_zone=create` aggiungi `--var account=<nome>` (account della zona condivisa; senza stack condiviso da generare `--var account` è un errore); la zona creata è leggibile solo dagli stack dello stesso account: con account diversi usa `existing:<zone_id>` per ambiente. Il generatore non sovrascrive file esistenti salvo `--force`, che chiede l'utente. Per vedere le differenze con una versione più recente del kit: `--upgrade`.
4. **Personalizzazioni** solo con gli strumenti di modifica dei file, mai con redirect o `sed -i` da shell: ogni scrittura passa dalle regole. Le più comuni nel blocco `module "spa"` dello stack: `content_security_policy` (aggiungi solo le sorgenti davvero usate, es. `connect-src` verso l'identity provider), `waf_rate_limit`, `price_class`. Mantieni OAC (mai `s3_origin_config` né l'endpoint website), `redirect-to-https`, `TLSv1.2_2021`, la CloudFront Function al posto delle `custom_error_response` 403/404 (limite: una rotta con un punto nell'ultimo segmento, es. `/utenti/mario.rossi`, è trattata come file e dà 404; evita i punti nell'ultimo segmento o adatta la funzione), i log v2 e `web_acl_id = var.waf_enabled ? aws_wafv2_web_acl.this[0].arn : null`.
5. **Controlla**: `python3 -B <kit>/scripts/arch_check.py . --external` e correggi la causa di ogni finding (mai soppressioni inline). Se mancano strumenti esterni proponi `/kynfra:kynfra-tools`.
6. **Riepiloga** in poche righe:
   - lock dei provider: il primo stop gate (o la CI) crea un `.terraform.lock.hcl` in ogni stack nuovo; l'agente non può scriverli (`protected-files`): ricorda all'utente di committarli;
   - file creati (modulo, stack per ambiente, eventuale `envs/shared/dns`) e output di ogni stack: `bucket_name`, `distribution_id`, `distribution_domain_name` (li usa il deploy del frontend, es. kyfes); della zona: `zone_id`, `zone_name`, `name_servers`;
   - costi: CloudFront e S3 a consumo, WAF (web ACL, regole e richieste) dove attivo, hosted zone e log delle query DNS;
   - comandi che esegue il DevOps con le sue credenziali (tu non li lanci): con `create`, prima `cd <infra_root>/envs/shared/dns && terraform init && terraform plan -out=dns.tfplan && terraform apply dns.tfplan`; con `api_origin=backend`, prima lo stack backend; poi per ogni ambiente `cd <infra_root>/envs/<env>/spa && terraform init && terraform plan -out=spa.tfplan && terraform apply spa.tfplan` (o `tofu`);
   - passi manuali: delegare i `name_servers` della zona dal registrar o dalla zona padre prima dell'apply degli stack spa (altrimenti la validazione ACM non termina); nel deploy caricare gli asset con hash con `Cache-Control: public, max-age=31536000, immutable` e `index.html` con `no-cache`, poi invalidare `/index.html`; DNSSEC della zona, se richiesto, è un passo del DevOps.
