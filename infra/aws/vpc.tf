# =============================================================================
# EvilTwin — Two-Subnet VPC for Deception Platform
# =============================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5"
}

provider "aws" {
  region = var.aws_region
}

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------
resource "aws_vpc" "eviltwin" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name    = "eviltwin-vpc"
    Project = "eviltwin"
  }
}

# ---------------------------------------------------------------------------
# Internet Gateway
# ---------------------------------------------------------------------------
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.eviltwin.id

  tags = {
    Name    = "eviltwin-igw"
    Project = "eviltwin"
  }
}

# ---------------------------------------------------------------------------
# Subnets — public (services) and private (honeypots)
# ---------------------------------------------------------------------------
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.eviltwin.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name    = "eviltwin-public"
    Project = "eviltwin"
    Tier    = "services"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.eviltwin.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.aws_region}a"

  tags = {
    Name    = "eviltwin-private"
    Project = "eviltwin"
    Tier    = "deception"
  }
}

# ---------------------------------------------------------------------------
# Route Tables
# ---------------------------------------------------------------------------
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.eviltwin.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "eviltwin-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Private subnet gets no internet route — honeypots are isolated
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.eviltwin.id
  tags   = { Name = "eviltwin-private-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------
resource "aws_security_group" "backend" {
  name_prefix = "eviltwin-backend-"
  vpc_id      = aws_vpc.eviltwin.id

  ingress {
    description = "API"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "eviltwin-backend-sg" }
}

resource "aws_security_group" "honeypot" {
  name_prefix = "eviltwin-honeypot-"
  vpc_id      = aws_vpc.eviltwin.id

  ingress {
    description = "SSH honeypot"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "FTP"
    from_port   = 21
    to_port     = 21
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP honeypot"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SMB"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # No egress — honeypots must not reach the internet
  tags = { Name = "eviltwin-honeypot-sg" }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
output "vpc_id" {
  value = aws_vpc.eviltwin.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "private_subnet_id" {
  value = aws_subnet.private.id
}
