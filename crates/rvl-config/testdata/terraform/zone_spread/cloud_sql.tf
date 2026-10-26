resource "google_sql_database_instance" "regional" {
  settings {
    tier              = "db-custom-2-7680"
    availability_type = "REGIONAL"
  }
}

resource "google_sql_database_instance" "zonal" {
  settings {
    tier              = "db-f1-micro"
    availability_type = "ZONAL"
  }
}

resource "google_sql_database_instance" "bare" {
  settings {
    tier = "db-f1-micro"
  }
}

resource "google_sql_database_instance" "from_var" {
  settings {
    tier              = "db-f1-micro"
    availability_type = var.availability_type
  }
}

resource "google_sql_database_instance" "from_expr" {
  settings {
    tier              = "db-f1-micro"
    availability_type = var.ha ? "REGIONAL" : "ZONAL"
  }
}
