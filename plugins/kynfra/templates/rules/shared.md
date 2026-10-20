---
paths:
  - "__PATH_PREFIX__**/*.tf"
  - "__PATH_PREFIX__**/*.tfvars"
  - "__PATH_PREFIX__**/*.tf.json"
---

# Regole condivise per l'infrastruttura (kynfra)

- Layout ammesso sotto `__INFRA_ROOT__`: `bootstrap/`, `modules/<pattern>/` (main, variables, outputs, versions, README), `envs/<env>/<stack>/` (backend, providers, versions, main, variables, `terraform.tfvars`, outputs, lock file), `envs/shared/<stack>/`, `native/<pattern>/`. Gli ambienti ammessi sono quelli in `.kynfra/config.json`.
- Uno stack per pattern e ambiente, ognuno con il suo stato; gli stack leggono gli output degli altri con `terraform_remote_state`.
- Backend S3 con `encrypt = true` e `use_lockfile = true`, chiave `<progetto>/<env>/<stack>.tfstate`. Backend locale solo in `bootstrap/`.
- `required_version` e `required_providers` con vincolo `~>`; il lock file `.terraform.lock.hcl` lo rigenera solo `terraform init`. Moduli locali (`../../modules/...`); nessun modulo di terze parti.
- Nomi delle risorse prefissati `<progetto>-<env>`. Differenze tra ambienti solo nei `tfvars`.
- Variabili sempre con `type` e `description`; `validation` dove il dominio è chiuso. Nomi, CIDR, porte e domini in `locals` o variabili, mai ripetuti come letterali.
- Niente `local-exec`/`remote-exec`. Niente soppressioni inline: le eccezioni stanno in `.kynfra/config.json`.
- Non eseguire mai `apply`, `plan`, `destroy`, `import` o `init` con backend reale.
