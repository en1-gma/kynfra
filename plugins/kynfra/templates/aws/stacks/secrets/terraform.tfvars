project              = "{{ project }}"
environment          = "{{ environment }}"
region               = "{{ region }}"
account_id           = "{{ account_id }}"
owner                = "{{ owner }}"
cost_center          = "{{ cost_center }}"
recovery_window_days = {{ recovery_window_days }}
replica_region       = "{{ replica_region }}"

# Esempio: un segreto segnaposto. I workload leggono con una policy identity sul proprio ruolo (output secret_arns e kms_key_arn);
# readers è un'aggiunta facoltativa alla resource policy, con ARN di ruoli già esistenti.
secrets = {
  app-db = {
    description = "Credenziali del database dell'applicazione"
    readers     = []
    # rotation_lambda_arn = "arn:aws:lambda:{{ region }}:{{ account_id }}:function:<funzione-di-rotazione>"
  }
}
