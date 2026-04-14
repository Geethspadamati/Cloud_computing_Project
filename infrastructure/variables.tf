variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "target_ec2_ip" {
  description = "The public IP alias of Person 1's EC2 target running the vulnerable app"
  type        = string
  default     = "3.144.240.191"
}

variable "kinesis_firehose_arn" {
  description = "The ARN of the Kinesis Firehose stream created by Person 4 for WAF logs"
  type        = string
  default     = "arn:aws:firehose:us-east-2:867490540204:deliverystream/aws-waf-logs-sqli-logs-to-s3"
}
