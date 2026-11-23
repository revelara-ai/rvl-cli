# M2a: wildcard grants in AWS policy documents.
resource "aws_iam_policy" "admin" {
  name = "admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "s3_all" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*"]
      Resource = [aws_s3_bucket.data.arn]
    }]
  })
}

resource "aws_iam_user_policy" "describe" {
  user   = aws_iam_user.deploy.name
  policy = <<-EOT
    {
      "Version": "2012-10-17",
      "Statement": [
        {"Effect": "Allow", "Action": ["ec2:DescribeInstances"], "Resource": "*"},
        {"Effect": "Deny", "Action": "*", "Resource": "*"}
      ]
    }
  EOT
}

resource "aws_iam_group_policy" "scoped" {
  group = aws_iam_group.ops.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["arn:aws:s3:::data/*"]
    }]
  })
}

resource "aws_iam_policy" "from_file" {
  name   = "from-file"
  policy = file("${path.module}/policy.json")
}

resource "aws_iam_policy" "from_doc" {
  name   = "from-doc"
  policy = data.aws_iam_policy_document.scoped.json
}

resource "aws_iam_role_policy" "templated" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = var.actions
      Resource = "*"
    }]
  })
}

data "aws_iam_policy_document" "wide" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "scoped" {
  statement {
    actions   = ["sqs:SendMessage"]
    resources = ["arn:aws:sqs:us-east-1:1:jobs"]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "dynamic" {
  dynamic "statement" {
    for_each = var.statements
    content {
      actions   = statement.value.actions
      resources = ["*"]
    }
  }
}
