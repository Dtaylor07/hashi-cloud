provider "aws" {
    region = "ca-central-1"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }

  backend "remote" {
    organization = "dhaval-academy"
    workspaces {
      name = "learn-terraform"
    }
  }
}