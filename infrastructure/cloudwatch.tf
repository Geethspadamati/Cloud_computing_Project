resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-sqli-project"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "app_logs" {
  name              = "/sqli-project/app-logs"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "lambda_detections" {
  name              = "/sqli-project/lambda-detections"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/vpc/sqli-project-flow-logs"
  retention_in_days = 30
}

# Metric Filters
resource "aws_cloudwatch_log_metric_filter" "union_count" {
  name           = "sqli-union-count"
  pattern        = "?UNION ?union"
  log_group_name = aws_cloudwatch_log_group.waf_logs.name

  metric_transformation {
    name      = "UnionSelectCount"
    namespace = "SQLiDetection"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "blocked_count" {
  name           = "sqli-blocked-count"
  pattern        = "{ $.action = \"BLOCK\" }"
  log_group_name = aws_cloudwatch_log_group.waf_logs.name

  metric_transformation {
    name      = "BlockedRequestCount"
    namespace = "SQLiDetection"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "sleep_count" {
  name           = "sqli-sleep-count"
  pattern        = "?SLEEP ?sleep"
  log_group_name = aws_cloudwatch_log_group.waf_logs.name

  metric_transformation {
    name      = "SleepAttackCount"
    namespace = "SQLiDetection"
    value     = "1"
  }
}

resource "aws_cloudwatch_log_metric_filter" "schema_count" {
  name           = "sqli-schema-count"
  pattern        = "information_schema"
  log_group_name = aws_cloudwatch_log_group.waf_logs.name

  metric_transformation {
    name      = "SchemaProbeCount"
    namespace = "SQLiDetection"
    value     = "1"
  }
}

# CloudWatch Alarm
resource "aws_cloudwatch_metric_alarm" "critical_attack" {
  alarm_name          = "sqli-critical-attack-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnionSelectCount"
  namespace           = "SQLiDetection"
  period              = "60"
  statistic           = "SampleCount"
  threshold           = "5"
  alarm_description   = "Alarm when UnionSelectCount >= 5 in 1 minute"
}

# Dashboard
resource "aws_cloudwatch_dashboard" "security_dashboard" {
  dashboard_name = "sqli-security-dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            [ "AWS/WAFV2", "AllowedRequests", "WebACL", "sqli-detection-waf", "Region", "us-east-2", "Rule", "ALL" ],
            [ ".", "BlockedRequests", ".", ".", ".", ".", ".", "." ],
            [ ".", "BlockedRequests", ".", ".", ".", ".", "Rule", "AWSManagedRulesSQLiRuleSetMetric", { "label": "DDoS/Flood Blocks" } ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-2"
          title   = "Requests Per Minute"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            [ "SQLiDetection", "UnionSelectCount" ],
            [ ".", "BlockedRequestCount" ],
            [ ".", "SleepAttackCount" ],
            [ ".", "SchemaProbeCount" ]
          ]
          view    = "timeSeries"
          stacked = false
          region  = "us-east-2"
          title   = "SQLi Detections by Type"
        }
      }
    ]
  })
}

resource "aws_iam_role" "cloudwatch_to_kinesis_role" {
  name = "cloudwatch_to_kinesis_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudwatch_to_kinesis_policy" {
  name = "cloudwatch_to_kinesis_policy"
  role = aws_iam_role.cloudwatch_to_kinesis_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kinesis:PutRecord"
        ]
        Effect = "Allow"
        Resource = aws_kinesis_stream.sqli_waf_logs.arn
      }
    ]
  })
}

resource "aws_cloudwatch_log_subscription_filter" "waf_logs_to_kinesis" {
  name            = "waf-logs-to-kinesis"
  log_group_name  = aws_cloudwatch_log_group.waf_logs.name
  filter_pattern  = "" # match everything
  destination_arn = aws_kinesis_stream.sqli_waf_logs.arn
  role_arn        = aws_iam_role.cloudwatch_to_kinesis_role.arn
}

# reviewed
