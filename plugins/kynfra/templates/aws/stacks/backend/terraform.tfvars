project                = "{{ project }}"
environment            = "{{ environment }}"
region                 = "{{ region }}"
account_id             = "{{ account_id }}"
owner                  = "{{ owner }}"
cost_center            = "{{ cost_center }}"
state_bucket           = "{{ state_bucket }}"
kybes_root             = "{{ kybes_root }}"
openapi_path           = "{{ kybes_openapi }}"
has_db                 = {{ kybes_has_db }}
authorizer             = "{{ authorizer }}"
cognito_user_pool_arn  = "{{ cognito_user_pool_arn }}"
oidc_issuer            = "{{ oidc_issuer }}"
oidc_audience          = "{{ oidc_audience }}"
log_retention_days     = {{ log_retention_days }}
throttling_rate_limit  = {{ throttling_rate_limit }}
throttling_burst_limit = {{ throttling_burst_limit }}
waf_enabled            = {{ waf_enabled }}
deletion_protection    = {{ deletion_protection }}
kubernetes_namespace   = "{{ kubernetes_namespace }}"
db_instance_identifier = "{{ db_instance_identifier }}"
db_engine_family       = "{{ db_engine_family }}"

# Segreti dello stack secrets leggibili per contesto kybes o per job, es. { ordini = ["db"], "sync-giacenze" = ["db"] }
context_secrets = {}
