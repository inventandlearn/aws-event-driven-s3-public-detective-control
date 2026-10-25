# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "notification_email" {
  description = "Email address for SNS notifications"
  type        = string
  default     = "renedanny344@gmail.com"
}