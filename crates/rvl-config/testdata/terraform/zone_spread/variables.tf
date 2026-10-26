# No defaults: each value is a project setting this repository does not hold.
variable "multi_az" {}
variable "availability_type" {}
variable "location" {}
variable "second_zone" {}

variable "zones" {
  default = ["europe-west4-a", "europe-west4-b"]
}
