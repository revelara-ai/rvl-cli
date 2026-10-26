resource "google_container_cluster" "regional" {
  name     = "regional"
  location = "europe-west4"
}

resource "google_container_cluster" "zonal" {
  name     = "zonal"
  location = "us-central1-a"
}

resource "google_container_cluster" "bare" {
  name = "bare"
}

resource "google_container_cluster" "from_var" {
  name     = "from-var"
  location = var.location
}

resource "google_container_cluster" "from_expr" {
  name     = "from-expr"
  location = "${var.region}-b"
}

resource "google_container_node_pool" "three_zones" {
  cluster = google_container_cluster.regional.name
  node_locations = [
    "europe-west4-a",
    "europe-west4-b",
    "europe-west4-c",
  ]
}

resource "google_container_node_pool" "one_zone" {
  cluster        = google_container_cluster.zonal.name
  node_locations = ["us-central1-a"]
}

resource "google_container_node_pool" "bare" {
  cluster = google_container_cluster.regional.name
}

resource "google_container_node_pool" "from_var" {
  cluster        = google_container_cluster.regional.name
  node_locations = var.zones
}

resource "google_container_node_pool" "from_expr" {
  cluster        = google_container_cluster.regional.name
  node_locations = slice(data.google_compute_zones.up.names, 0, 2)
}

resource "google_container_node_pool" "mixed" {
  cluster        = google_container_cluster.regional.name
  node_locations = ["europe-west4-a", var.second_zone]
}
