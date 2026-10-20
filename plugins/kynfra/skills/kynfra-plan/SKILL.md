---
name: kynfra-plan
description: Plan an infrastructure change on AWS according to kynfra (stacks and files, state keys, variables per environment, accounts and tags, secrets, security rules, costs, commands for the DevOps). Use before writing Terraform for a new pattern, stack or change — especially in Codex, where it replaces the kynfra:architect agent.
---

# Pianificare una modifica con kynfra

Stai agendo da architetto dell'infrastruttura. In questo passo non scrivi codice né file.

1. Carica le regole della skill `kynfra-architecture` (leggi il suo `SKILL.md`) e `references/aws.md` per il pattern coinvolto.
2. Leggi `.kynfra/config.json` (`infra_root`, `project`, `iac`, `region`, `environments`, `accounts`, `tags`, `exceptions`).
3. Esplora ciò che esiste sotto `infra_root`: `bootstrap/`, `modules/`, `envs/*/*`, `envs/shared/*`, `native/`, i `tfvars` di ogni ambiente e gli output degli stack da cui dipendi (es. `network` per `elb` ed `eks`; se manca, proponi di generarlo prima). Nei repository kybes leggi anche `schemas/openapi.yaml` e `services/`, `jobs/` per il pattern `backend`. Consulta Context7 o il registry Terraform per gli argomenti di cui non sei certo.
4. Scrivi il piano nel formato obbligatorio (sez. 10 della skill):
   1. tabella `Risorsa | Pattern/modulo | Stack | Ambienti | Differenze tra ambienti | Controlli di sicurezza | Dipendenze (remote state)`;
   2. variabili e output nuovi;
   3. segreti coinvolti e come arriva il valore;
   4. impatto sui costi (NAT, EKS, ALB, WAF, endpoint VPC);
   5. comandi che il DevOps dovrà eseguire (`init`, `plan`, `apply`) e passaggi manuali (delega NS, valori dei segreti);
   6. violazioni richieste e alternative conformi;
   7. task piccoli e indipendenti, ciascuno con i file.
5. Non pianificare mai `apply`, `plan`, `import` o `state`: li esegue il DevOps. Se servono strumenti esterni mancanti, aggiungi un task "installare con `/kynfra:tools`".
6. In Codex esegui ogni task con l'agente `kynfra_implementer` se disponibile, altrimenti implementalo tu seguendo `kynfra-architecture`; chiudi con `$kynfra-review`.
