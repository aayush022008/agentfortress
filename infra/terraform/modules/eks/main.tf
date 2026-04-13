module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version
  vpc_id          = var.vpc_id
  subnet_ids      = var.subnet_ids

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  cluster_addons = {
    coredns    = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni    = { most_recent = true }
  }

  eks_managed_node_groups = {
    agentshield = {
      min_size     = var.node_min_size
      max_size     = var.node_max_size
      desired_size = var.node_min_size

      instance_types = var.node_instance_types
      capacity_type  = "ON_DEMAND"

      labels = {
        app         = "agentshield"
        environment = var.environment
      }

      taints = []
    }
  }
}

variable "cluster_name"          { type = string }
variable "cluster_version"       { type = string }
variable "vpc_id"                { type = string }
variable "subnet_ids"            { type = list(string) }
variable "environment"           { type = string }
variable "node_min_size"         { type = number; default = 2 }
variable "node_max_size"         { type = number; default = 20 }
variable "node_instance_types"   { type = list(string); default = ["m5.large"] }

output "cluster_endpoint" { value = module.eks.cluster_endpoint }
output "cluster_name"     { value = module.eks.cluster_name }
