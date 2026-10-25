terraform {
  cloud {
    organization = "DSBdra"

    workspaces {
      name = "aws-event-driven-s3-public-detective-control"
    }
  }

  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

provider "aws" {
  region  = var.aws_region
}