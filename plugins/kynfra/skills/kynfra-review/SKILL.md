---
name: kynfra-review
description: Independent review of infrastructure changes against kynfra rules (layout, remote state, tags, accounts, secrets, S3/CloudFront/ALB/EKS/ECR/API/Lambda hardening, exceptions). Use after implementing a change, before committing or opening a PR — in Codex it replaces the kynfra:reviewer agent.
---

# Revisionare l'infrastruttura con kynfra

Revisiona come se non avessi scritto il codice. Non modificare file durante la revisione.

1. Carica le regole di `kynfra-architecture` e `references/aws.md`.
2. Trova le modifiche: `git diff` e `git diff --staged` (o i file indicati dall'utente).
3. Esegui i controlli automatici e riporta l'output:
   - `python3 -B tools/kynfra/plugins/kynfra/scripts/arch_check.py . --strict --external`
   - ogni comando in `stop_gate.commands` di `.kynfra/config.json` (fmt, validate, tflint, scanner).
   Se uno strumento esterno manca, dillo e proponi `/kynfra:tools`: non installarlo tu.
4. Percorri la checklist di consegna (sez. 9 della skill) e ciò che l'automazione non vede: ruoli IAM più ampi del necessario pur senza `*`; trust policy e resource policy che aprono a principal troppo larghi; segreti passati come variabili d'ambiente, output o `tfvars`; valori di prod che dipendono da espressioni invece che da `tfvars`; CIDR e porte aperti più del necessario; stack che condividono stato o dipendono da output inesistenti; risorse senza `lifecycle`/protezione dove un errore cancellerebbe dati (database, bucket, chiavi KMS); costi fissi non dichiarati (NAT, EKS, ALB, WAF); eccezioni in config senza motivo o scadenza; soppressioni inline; comandi mutanti eseguiti durante il lavoro (`apply`, `plan`, CLI cloud, lettura di segreti); differenze tra ambienti fuori dai `tfvars`.
5. Rispondi con:
   - **Esito**: APPROVATO oppure DA CORREGGERE
   - **Violazioni bloccanti** (regola, file:riga, correzione proposta)
   - **Osservazioni non bloccanti**

Non approvare se manca anche una sola voce bloccante o se un controllo automatico fallisce.
