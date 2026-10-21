# Module `eks`

Amazon EKS cluster for the workloads (kybes microservices and jobs), in the private subnets of the `network` stack, plus the `addons` submodule (`modules/eks/addons`) used by the `kubernetes-addons` stack.

| Area | What the module creates |
|---|---|
| Control plane | `<project>-<env>` cluster on `kubernetes_version` (default `1.36`: the latest minor supported by EKS and by the pinned KEDA chart), `endpoint_private_access = true`, public endpoint only when `public_endpoint_cidrs` is not empty (`0.0.0.0/0` and `::/0` rejected), `deletion_protection` (mandatory in prod), `upgrade_policy { support_type = var.support_type }` (default `STANDARD`: automatic upgrade at the end of standard support instead of paid extended support), `bootstrap_self_managed_addons = false` (every add-on is an EKS managed add-on). |
| Encryption | Kubernetes Secrets envelope-encrypted with a dedicated KMS key (`alias/<project>-<env>-eks-secrets`); control plane logs encrypted with `alias/<project>-<env>-eks-logs`; node volumes with `alias/<project>-<env>-eks-ebs` (usable by any principal of the account only through EC2, like `aws/ebs`, so the Auto Scaling and node group service-linked roles work). Rotation enabled on all keys. |
| Logs | Log group `/aws/eks/<cluster>/cluster` created before the cluster with `log_retention_days` (at least 365 in prod) and KMS; all five control plane log types (`api`, `audit`, `authenticator`, `controllerManager`, `scheduler`). |
| Access | `authentication_mode = "API"` and `bootstrap_cluster_creator_admin_permissions = false`: no `aws-auth` ConfigMap, no implicit admin. Every ARN in `admin_principals` (same account, checked at plan time) gets an access entry with `AmazonEKSClusterAdminPolicy` on the cluster scope. Karpenter nodes join through an `EC2_LINUX` access entry for their role; managed node groups get theirs from EKS. |
| System nodes | One managed node group per `node_groups` entry (the stack creates `system`) in the private subnets, AL2023 AMI, on-demand, launch template with `http_tokens = "required"` and `http_put_response_hop_limit = 1` (pods cannot reach the node credentials through IMDS), encrypted gp3 root volume with the EBS key, the cluster security group plus a dedicated node security group (`node_security_group_id`, no rules: allow the pod ports from the load balancer security group here). Node role: `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, `AmazonEC2ContainerRegistryPullOnly`. |
| Managed add-ons | `vpc-cni`, `kube-proxy`, `eks-pod-identity-agent` before the nodes; `coredns` and `aws-ebs-csi-driver` after them. Version: the most recent one compatible with the cluster version (`data "aws_eks_addon_version"`, `most_recent = true`), or the one pinned in `addon_versions`. A new add-on build shows up in `plan` as an in-place update. |
| Pod Identity | One role per system component, trusted by `pods.eks.amazonaws.com` only for this cluster ARN, namespace and service account (Pod Identity session tags, keep them enabled on the associations): `kube-system/aws-load-balancer-controller` (official v3.6.0 IAM policy), `kube-system/karpenter` (official controller policy, scoped by the cluster tags, `iam:PassRole` only on the Karpenter node role), `keda/keda-operator` (`sqs:GetQueueAttributes` on `<project>-<env>-*` queues), `kube-system/ebs-csi-controller-sa` (`AmazonEBSCSIDriverPolicyV2`, associated by the add-on). No OIDC provider (no IRSA). |
| Karpenter | Node role `<project>-<env>-karpenter-node`, interruption queue `<project>-<env>` (SQS-managed SSE, 5-minute retention, TLS-only, writes only from EventBridge) and EventBridge rules for Spot interruptions, rebalance recommendations, instance state changes, capacity reservation interruptions and AWS Health events. |

Inputs: `project`, `environment`, `kubernetes_version`, `vpc_id`, `subnet_ids`, `public_endpoint_cidrs`, `admin_principals`, `node_groups` (map of `{instance_types, min_size, max_size, desired_size, ami_type = "AL2023_x86_64_STANDARD", disk_size = 50}`), `log_retention_days`, `deletion_protection`, `addon_versions`, `support_type` (`STANDARD` or `EXTENDED`). The AWS Load Balancer Controller policy lives in `iam_lb_controller.tf`, the only file covered by the scanner baseline entries `CKV_AWS_290`/`CKV_AWS_355`.

Outputs: `cluster_name`, `cluster_arn`, `cluster_endpoint`, `cluster_ca`, `cluster_security_group_id`, `node_security_group_id`, `node_subnet_ids`, `node_kms_key_arn`, `karpenter_queue_name`, `karpenter_node_role_name`, `pod_role_arns`.

## Submodule `addons`

Used only by the `kubernetes-addons` stack (Helm provider authenticated with the short-lived token of `data "aws_eks_cluster_auth"`). Releases, with chart versions pinned from the kit `versions.json` (update with `generate.py --upgrade`):

| Release | Chart | Namespace | Notes |
|---|---|---|---|
| `aws-load-balancer-controller` | `https://aws.github.io/eks-charts` `aws-load-balancer-controller` | `kube-system` | `clusterName`, `region` and `vpcId` passed explicitly (pods have no IMDS access). With the `elb` pattern, register pods in its IP target group with a `TargetGroupBinding`. |
| `karpenter-crd`, `karpenter` | `oci://public.ecr.aws/karpenter` | `kube-system` | CRDs from the dedicated chart (Helm never upgrades `crds/`), `skip_crds = true` on the controller; `settings.clusterName`, `settings.interruptionQueue`, `AWS_REGION`. |
| `keda` | `https://kedacore.github.io/charts` `keda` | `keda` | Operator service account `keda-operator` (Pod Identity role). |

Inputs: `cluster_name`, `region`, `vpc_id`, `karpenter_queue_name`, `controller_replicas` (default 2). Output: `releases`.

## Karpenter NodePool and EC2NodeClass

Karpenter launches nodes only for a `NodePool` and its `EC2NodeClass`. They describe the workload capacity (instance families, Spot or on-demand, limits), so they belong to the workloads (kybes), not to this module, which cannot apply Kubernetes manifests without an extra provider. A compliant starting point, with the stack outputs in angle brackets and the AMI alias pinned to a tested release (never `@latest` in prod):

```yaml
apiVersion: karpenter.k8s.aws/v1
kind: EC2NodeClass
metadata:
  name: default
spec:
  role: <karpenter_node_role_name>
  amiSelectorTerms:
    - alias: al2023@<tested AMI release, vYYYYMMDD>
  subnetSelectorTerms:
    - id: <node_subnet_ids[0]>
    - id: <node_subnet_ids[1]>
  securityGroupSelectorTerms:
    - id: <cluster_security_group_id>
    - id: <node_security_group_id>
  metadataOptions:
    httpEndpoint: enabled
    httpTokens: required
    httpPutResponseHopLimit: 1
  blockDeviceMappings:
    - deviceName: /dev/xvda
      ebs:
        volumeSize: 50Gi
        volumeType: gp3
        encrypted: true
        kmsKeyID: <node_kms_key_arn>
---
apiVersion: karpenter.sh/v1
kind: NodePool
metadata:
  name: default
spec:
  template:
    spec:
      nodeClassRef:
        group: karpenter.k8s.aws
        kind: EC2NodeClass
        name: default
      requirements:
        - key: kubernetes.io/arch
          operator: In
          values: ["amd64"]
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
  limits:
    cpu: "100"
  disruption:
    consolidationPolicy: WhenEmptyOrUnderutilized
```

## Network notes

- The API server endpoint is private by default: the `kubernetes-addons` stack must run from a network that reaches it (VPN, Direct Connect or a bastion in the VPC, with 443 allowed on `cluster_security_group_id`) or from an IP listed in `public_endpoint_cidrs`.
- Nodes reach AWS APIs (EKS Auth for Pod Identity, EC2, ELB, SQS) and public registries (`public.ecr.aws`, `ghcr.io` for KEDA) through the NAT gateways of the `network` stack; private ECR pulls use the ECR interface endpoints and the S3 gateway endpoint (ECR layer bucket). EKS-optimized AL2023 nodes need no other AWS-owned S3 bucket to boot; in-place `dnf` updates from the Amazon Linux repositories are not expected (nodes are replaced with a new AMI) and would be refused by the S3 endpoint policy.
- The workload pods use the node security groups (VPC CNI without security groups for pods): allow the load balancer `security_group_id` on the pod port in `node_security_group_id`.
