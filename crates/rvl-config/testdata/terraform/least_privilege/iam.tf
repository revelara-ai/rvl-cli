# M2a / S1: the class of a GCP role grant.
resource "google_project_iam_member" "owner" {
  project = "p"
  role    = "roles/owner"
  member  = "serviceAccount:app@p.iam.gserviceaccount.com"
}

resource "google_folder_iam_binding" "editor" {
  folder  = "folders/1"
  role    = "roles/editor"
  members = ["group:ops@example.com"]
}

resource "google_organization_iam_member" "viewer" {
  org_id = "1"
  role   = "roles/viewer"
  member = "group:audit@example.com"
}

resource "google_project_iam_member" "custom" {
  project = "p"
  role    = "projects/p/roles/appReader"
  member  = "serviceAccount:app@p.iam.gserviceaccount.com"
}

resource "google_project_iam_binding" "predefined" {
  project = "p"
  role    = var.reader_role
  members = ["serviceAccount:app@p.iam.gserviceaccount.com"]
}

resource "google_project_iam_member" "from_each" {
  for_each = toset(var.roles)
  project  = "p"
  role     = each.value
  member   = "serviceAccount:app@p.iam.gserviceaccount.com"
}
