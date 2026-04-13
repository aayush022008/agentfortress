module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 6.0"

  identifier = var.identifier

  engine            = "postgres"
  engine_version    = var.engine_version
  instance_class    = var.instance_class
  allocated_storage = 100
  storage_encrypted = true

  db_name  = var.db_name
  username = var.db_username
  port     = 5432

  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.agentshield.name

  backup_retention_period = 30
  deletion_protection     = var.environment == "production"
  multi_az                = var.environment == "production"

  performance_insights_enabled = true
  monitoring_interval          = 60

  parameters = [
    { name = "log_min_duration_statement", value = "1000" },
    { name = "shared_preload_libraries", value = "pg_stat_statements" },
  ]
}

resource "aws_db_subnet_group" "agentshield" {
  name       = "agentshield-${var.identifier}"
  subnet_ids = var.subnet_ids
}

resource "aws_security_group" "rds" {
  name   = "agentshield-rds-${var.identifier}"
  vpc_id = var.vpc_id

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

variable "identifier"     { type = string }
variable "engine_version" { type = string; default = "16.1" }
variable "instance_class" { type = string; default = "db.t3.medium" }
variable "vpc_id"         { type = string }
variable "subnet_ids"     { type = list(string) }
variable "db_name"        { type = string; default = "agentshield" }
variable "db_username"    { type = string; default = "agentshield" }
variable "environment"    { type = string }

output "endpoint"   { value = module.db.db_instance_endpoint; sensitive = true }
output "db_name"    { value = var.db_name }
