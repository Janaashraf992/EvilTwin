variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the EvilTwin VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR for the public (services) subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR for the private (honeypot) subnet — no internet access"
  type        = string
  default     = "10.0.2.0/24"
}

variable "ecs_task_cpu" {
  description = "CPU units for ECS tasks (1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "ecs_task_memory" {
  description = "Memory in MiB for ECS tasks"
  type        = number
  default     = 1024
}

variable "postgres_password" {
  description = "Password for the PostgreSQL database"
  type        = string
  sensitive   = true
}

variable "ipinfo_token" {
  description = "ipinfo.io API token"
  type        = string
  sensitive   = true
}

variable "abuseipdb_api_key" {
  description = "AbuseIPDB API key"
  type        = string
  sensitive   = true
}

variable "splunk_hec_token" {
  description = "Splunk HEC token"
  type        = string
  sensitive   = true
  default     = ""
}

variable "canary_webhook_secret" {
  description = "Canary token webhook HMAC secret"
  type        = string
  sensitive   = true
}
