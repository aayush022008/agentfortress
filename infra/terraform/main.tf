terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "agentshield-terraform-state"
    key    = "production/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "AgentShield"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = "agentshield-${var.environment}"
  cidr = var.vpc_cidr

  azs             = var.availability_zones
  private_subnets = var.private_subnet_cidrs
  public_subnets  = var.public_subnet_cidrs

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "production"
  enable_dns_hostnames   = true
  enable_dns_support     = true
}

# EKS Cluster
module "eks" {
  source = "./modules/eks"

  cluster_name    = "agentshield-${var.environment}"
  cluster_version = var.eks_cluster_version
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  environment     = var.environment
  node_min_size   = var.eks_node_min
  node_max_size   = var.eks_node_max
  node_instance_types = var.eks_node_instance_types
}

# RDS PostgreSQL
module "rds" {
  source = "./modules/rds"

  identifier      = "agentshield-${var.environment}"
  engine_version  = "16.1"
  instance_class  = var.rds_instance_class
  vpc_id          = module.vpc.vpc_id
  subnet_ids      = module.vpc.private_subnets
  db_name         = "agentshield"
  db_username     = "agentshield"
  environment     = var.environment
}

# ElastiCache Redis
resource "aws_elasticache_replication_group" "agentshield" {
  replication_group_id = "agentshield-${var.environment}"
  description          = "AgentShield Redis cache"
  node_type            = var.redis_node_type
  num_cache_clusters   = var.environment == "production" ? 3 : 1
  engine_version       = "7.2"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.agentshield.name
  security_group_ids   = [aws_security_group.redis.id]

  at_rest_encryption_enabled  = true
  transit_encryption_enabled  = true
  automatic_failover_enabled  = var.environment == "production"

  log_delivery_configuration {
    destination      = aws_cloudwatch_log_group.redis.name
    destination_type = "cloudwatch-logs"
    log_format       = "json"
    log_type         = "slow-log"
  }
}

resource "aws_elasticache_subnet_group" "agentshield" {
  name       = "agentshield-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "redis" {
  name   = "agentshield-redis-${var.environment}"
  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudwatch_log_group" "redis" {
  name              = "/agentshield/${var.environment}/redis"
  retention_in_days = 30
}

# S3 for evidence packages and exports
resource "aws_s3_bucket" "agentshield_data" {
  bucket = "agentshield-data-${var.environment}-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "agentshield_data" {
  bucket = aws_s3_bucket.agentshield_data.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "agentshield_data" {
  bucket = aws_s3_bucket.agentshield_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

data "aws_caller_identity" "current" {}
