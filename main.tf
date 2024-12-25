resource "aws_vpc" "name" {
  for_each   = var.env
  cidr_block = "10.7.8.0/24"

  tags = {
    Name = each.key
  }
}

variable "env" {
  default = {
    dev  = "dev-vpc"
    prod = "prod-vpc"
  }
}

resource "aws_s3_bucket" "main" {
  bucket = "dhval-tst-terraform-cloud-hashi-1"
}