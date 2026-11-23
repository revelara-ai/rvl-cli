# M3: the identity GKE nodes run as.
resource "google_container_node_pool" "bare" {
  cluster = google_container_cluster.main.id
}

resource "google_container_node_pool" "compute_default" {
  cluster = google_container_cluster.main.id
  node_config {
    service_account = "123456789-compute@developer.gserviceaccount.com"
  }
}

resource "google_container_node_pool" "broad_scope" {
  cluster = google_container_cluster.main.id
  node_config {
    service_account = "nodes@p.iam.gserviceaccount.com"
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
  }
}

resource "google_container_node_pool" "dedicated" {
  cluster = google_container_cluster.main.id
  node_config {
    service_account = var.node_account
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
    ]
  }
}

resource "google_container_node_pool" "from_ref" {
  cluster = google_container_cluster.main.id
  node_config {
    service_account = google_service_account.nodes.email
  }
}

resource "google_container_cluster" "inline" {
  name     = "inline"
  location = "us-central1"
  node_config {
    machine_type = "e2-standard-4"
  }
}

resource "google_container_cluster" "pools_only" {
  name                     = "pools-only"
  location                 = "us-central1"
  remove_default_node_pool = true
  initial_node_count       = 1
}
