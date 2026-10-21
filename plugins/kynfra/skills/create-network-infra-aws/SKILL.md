---
name: create-network-infra-aws
description: Generate the AWS network foundation with kynfra (VPC on 2-3 AZs, public/private/isolated subnets, NAT, VPC endpoints, encrypted flow logs, empty default security group) as a network stack per environment. Use when the user runs /kynfra:create-network-infra-aws or asks for a VPC, subnets or networking on AWS.
---

# Creare la rete AWS (pattern `network`)

Genera il modulo `modules/network` e lo stack `envs/<env>/network` per ogni ambiente richiesto. Prima di scrivere o modificare codice carica le regole della skill `kynfra-architecture` (`SKILL.md` e `references/aws.md`, sezione `network`). Il kit si trova in `tools/kynfra/plugins/kynfra/` (nel repository del plugin: `plugins/kynfra/`); di seguito `<kit>`.

1. **Leggi lo stato**: `.kynfra/config.json` (`infra_root`, `project`, `region`, `environments`, `accounts`, `tags`, `iac`) e cosa esiste già sotto `infra_root`: `envs/*/network`, `bootstrap/`, i `tfvars` esistenti. Se `bootstrap/` manca, segnala che il backend S3 dello stato deve esistere prima dell'`init` degli stack e proponi di generarlo (`generate.py --pattern bootstrap`). Il pattern `network` non ha `requires`.
2. **Un solo giro di domande**, solo su ciò che manca:
   - ambienti da generare (default: tutti quelli in config);
   - `vpc_cidr` (default `10.0.0.0/16`, da /16 a /20; se nello stesso account esistono già altre VPC o c'è peering, scegli CIDR che non si sovrappongono);
   - `az_count` (2 o 3; default 3 in prod, 2 altrove; per fissare i nomi delle zone usa `availability_zones` nei `tfvars`);
   - `nat_per_az` (default `true` in prod, `false` altrove: un NAT per zona costa di più ma regge il guasto di una zona);
   - `flow_log_retention_days` (default 365 in prod, 90 altrove).
   Gli ambienti già generati non vengono sovrascritti.
3. **Genera**:

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern network --provider aws --env dev,staging,prod [--var vpc_cidr=10.0.0.0/16]
   ```

   Per cambiare zone, NAT o retention in dev e staging genera quegli ambienti a parte, senza prod (le `--var` valgono per tutti gli ambienti del comando e non devono indebolire i default di prod):

   ```bash
   python3 -B <kit>/scripts/generate.py --pattern network --provider aws --env dev,staging [--var az_count=3] [--var nat_per_az=true] [--var flow_log_retention_days=180]
   ```

   I default di prod (3 zone, NAT per zona, retention 365) prevalgono sui default generali ma non su `--var`; in prod la retention dei flow log non può scendere sotto 365 giorni (validazione del modulo). Il generatore non sovrascrive file esistenti salvo `--force`, che chiede l'utente. Per vedere le differenze con una versione più recente del kit: `--upgrade`.
4. **Personalizzazioni** (altri endpoint, CIDR per ambiente diversi nei `tfvars`) solo con gli strumenti di modifica dei file, mai con redirect o `sed -i` da shell: ogni scrittura passa dalle regole. Mantieni letterali gli attributi di sicurezza, `enable_key_rotation = true`, la retention dei log e il security group di default senza regole.
5. **Controlla**: `python3 -B <kit>/scripts/arch_check.py . --external` e correggi la causa di ogni finding (mai soppressioni inline). Se mancano strumenti esterni proponi `/kynfra:kynfra-tools`.
6. **Riepiloga** in poche righe:
   - lock dei provider: il primo stop gate (o la CI) crea un `.terraform.lock.hcl` in ogni stack nuovo; l'agente non può scriverli (`protected-files`): ricorda all'utente di committarli;
   - file creati (modulo e stack per ambiente) e output di ogni stack: `vpc_id`, `public_subnet_ids`, `private_subnet_ids`, `isolated_subnet_ids`, `vpc_endpoint_sg_id`;
   - costi fissi: NAT gateway (uno per zona in prod) ed endpoint VPC interface (cinque per ogni zona);
   - comandi che esegue il DevOps con le sue credenziali, per ogni ambiente: `cd <infra_root>/envs/<env>/network && terraform init && terraform plan -out=network.tfplan && terraform apply network.tfplan` (o `tofu`). Tu non li lanci;
   - passi manuali: nessuno per la rete; ricorda che `elb` ed `eks` leggono questi output con `terraform_remote_state` (chiave `<progetto>/<env>/network.tfstate`) e che le subnet isolate non hanno uscita verso internet.
