# WAF requires stream names to start with aws-waf-logs-
resource "aws_kinesis_stream" "sqli_waf_logs" {
  name             = "aws-waf-logs-sqli-waf-logs"
  shard_count      = 2
  retention_period = 24

  stream_mode_details {
    stream_mode = "PROVISIONED"
  }
}

# IAM Role for Firehose to write to S3 and read from Kinesis
resource "aws_iam_role" "firehose_role" {
  name = "firehose_sqli_logs_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "firehose_policy" {
  name   = "firehose_sqli_logs_policy"
  role   = aws_iam_role.firehose_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.logs_archive.arn,
          "${aws_s3_bucket.logs_archive.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = [
          "kinesis:DescribeStream",
          "kinesis:GetShardIterator",
          "kinesis:GetRecords",
          "kinesis:ListShards"
        ]
        Resource = aws_kinesis_stream.sqli_waf_logs.arn
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "sqli_logs_to_s3" {
  name        = "aws-waf-logs-sqli-logs-to-s3"
  destination = "extended_s3"

  # We read from the Kinesis Data Stream (as defined in Person 4's step 8)
  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.sqli_waf_logs.arn
    role_arn           = aws_iam_role.firehose_role.arn
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.logs_archive.arn

    prefix              = "waf-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_output_prefix = "errors/"

    buffering_size     = 5
    buffering_interval = 300

    cloudwatch_logging_options {
      enabled = true
      log_group_name = aws_cloudwatch_log_group.waf_logs.name
      log_stream_name = "firehose-delivery"
    }
  }
}

# reviewed
