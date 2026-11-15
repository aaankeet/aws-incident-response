variable "project_name" {
  description = "Name of the cloud security project"
  type = string
  default = "aws-incident-response"
}

variable "aws_region" {
  description = "AWS Deployment region"
  type = string
  default = "ap-south-1"
}
