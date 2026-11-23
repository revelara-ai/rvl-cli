# M1: static long-lived service credentials.
resource "google_service_account_key" "ci" {
  service_account_id = google_service_account.ci.name
}

resource "google_service_account_key" "none" {
  service_account_id = google_service_account.ci.name
  count              = 0
}

resource "google_service_account_key" "maybe" {
  service_account_id = google_service_account.ci.name
  count              = var.create_key ? 1 : 0
}

resource "aws_iam_access_key" "deploy" {
  user = aws_iam_user.deploy.name
}

resource "aws_iam_access_key" "none" {
  user     = aws_iam_user.deploy.name
  for_each = []
}

resource "aws_iam_access_key" "per_user" {
  user     = each.value
  for_each = toset(var.users)
}
