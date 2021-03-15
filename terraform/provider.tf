terraform {

    required_version = "~> 0.14"

    backend "s3" {
        bucket  = "valheim-server-terraform-state"
        key     = "2-linuxgsm/terraform.tfstate"
        region  = "us-west-2"
        encrypt = true
    }

    required_providers {
        aws = {
            source  = "hashicorp/aws"
            version = "~> 3.0"
        }
    }

}

provider "aws" {

    region = local.region

}

data "aws_availability_zones" "available" {

}