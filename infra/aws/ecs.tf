# =============================================================================
# EvilTwin — ECS Task Definitions
# =============================================================================

# ---------------------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "eviltwin" {
  name = "eviltwin-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = { Project = "eviltwin" }
}

# ---------------------------------------------------------------------------
# IAM — Task Execution Role
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ecs_execution" {
  name = "eviltwin-ecs-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ---------------------------------------------------------------------------
# CloudWatch Log Group
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "eviltwin" {
  name              = "/ecs/eviltwin"
  retention_in_days = 30
  tags              = { Project = "eviltwin" }
}

# ---------------------------------------------------------------------------
# Backend Task Definition
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "backend" {
  family                   = "eviltwin-backend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.ecs_task_cpu
  memory                   = var.ecs_task_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name      = "backend"
    image     = "eviltwin-backend:latest"
    essential = true
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "POSTGRES_HOST", value = "eviltwin-postgres.local" },
      { name = "POSTGRES_PORT", value = "5432" },
      { name = "POSTGRES_DB", value = "eviltwin" },
      { name = "POSTGRES_USER", value = "eviltwin" },
    ]
    secrets = [
      { name = "POSTGRES_PASSWORD", valueFrom = "arn:aws:ssm:${var.aws_region}::parameter/eviltwin/db-password" },
      { name = "IPINFO_TOKEN", valueFrom = "arn:aws:ssm:${var.aws_region}::parameter/eviltwin/ipinfo-token" },
      { name = "ABUSEIPDB_API_KEY", valueFrom = "arn:aws:ssm:${var.aws_region}::parameter/eviltwin/abuseipdb-key" },
      { name = "CANARY_WEBHOOK_SECRET", valueFrom = "arn:aws:ssm:${var.aws_region}::parameter/eviltwin/canary-secret" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.eviltwin.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "backend"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 40
    }
  }])

  tags = { Project = "eviltwin" }
}

# ---------------------------------------------------------------------------
# Cowrie Honeypot Task Definition
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "cowrie" {
  family                   = "eviltwin-cowrie"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name      = "cowrie"
    image     = "eviltwin-cowrie:latest"
    essential = true
    portMappings = [{ containerPort = 22, protocol = "tcp" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.eviltwin.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "cowrie"
      }
    }
  }])

  tags = { Project = "eviltwin" }
}

# ---------------------------------------------------------------------------
# SDN Controller Task Definition
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "ryu" {
  family                   = "eviltwin-ryu"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([{
    name      = "ryu"
    image     = "eviltwin-ryu:latest"
    essential = true
    portMappings = [
      { containerPort = 6633, protocol = "tcp" },
      { containerPort = 8080, protocol = "tcp" },
    ]
    environment = [
      { name = "BACKEND_URL", value = "http://backend.eviltwin.local:8000" },
      { name = "HONEYPOT_IP", value = "10.0.2.10" },
      { name = "THREAT_REDIRECT_THRESHOLD", value = "2" },
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.eviltwin.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ryu"
      }
    }
  }])

  tags = { Project = "eviltwin" }
}

# ---------------------------------------------------------------------------
# ECS Services
# ---------------------------------------------------------------------------
resource "aws_ecs_service" "backend" {
  name            = "eviltwin-backend"
  cluster         = aws_ecs_cluster.eviltwin.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.public.id]
    security_groups  = [aws_security_group.backend.id]
    assign_public_ip = true
  }

  tags = { Project = "eviltwin" }
}

resource "aws_ecs_service" "cowrie" {
  name            = "eviltwin-cowrie"
  cluster         = aws_ecs_cluster.eviltwin.id
  task_definition = aws_ecs_task_definition.cowrie.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.private.id]
    security_groups  = [aws_security_group.honeypot.id]
    assign_public_ip = false
  }

  tags = { Project = "eviltwin" }
}
