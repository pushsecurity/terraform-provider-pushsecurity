# State has to persist between pipeline runs, so it lives in a remote backend.
# Any backend that stores state privately and locks it will do; S3 is one.
terraform {
  backend "s3" {
    bucket       = "example-push-terraform-state" # replace with your bucket
    key          = "push/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    use_lockfile = true
  }
}
