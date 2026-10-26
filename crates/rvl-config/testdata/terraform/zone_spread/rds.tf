resource "aws_db_instance" "spread" {
  engine   = "postgres"
  multi_az = true
}

resource "aws_db_instance" "single" {
  engine   = "postgres"
  multi_az = false
}

resource "aws_db_instance" "bare" {
  engine = "postgres"
}

resource "aws_db_instance" "from_var" {
  engine   = "postgres"
  multi_az = var.multi_az
}

resource "aws_db_instance" "from_expr" {
  engine   = "postgres"
  multi_az = local.env == "prod"
}
