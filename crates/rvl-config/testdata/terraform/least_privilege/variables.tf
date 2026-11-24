variable "create_key" {
  type    = bool
  default = false
}

variable "users" {
  type = list(string)
}

variable "roles" {
  type = list(string)
}

variable "reader_role" {
  type    = string
  default = "roles/storage.objectViewer"
}

variable "actions" {
  type = list(string)
}

variable "statements" {
  type = list(any)
}

variable "node_account" {
  type    = string
  default = "nodes@p.iam.gserviceaccount.com"
}
