resource "aws_sns_topic" "sqli_alerts" {
  name = "sql-injection-alerts"
}

# Team member email subscriptions — each must click confirmation link from AWS
resource "aws_sns_topic_subscription" "person1_email" {
  topic_arn = aws_sns_topic.sqli_alerts.arn
  protocol  = "email"
  endpoint  = var.team_email_1
}

resource "aws_sns_topic_subscription" "person2_email" {
  topic_arn = aws_sns_topic.sqli_alerts.arn
  protocol  = "email"
  endpoint  = var.team_email_2
}

resource "aws_sns_topic_subscription" "person3_email" {
  topic_arn = aws_sns_topic.sqli_alerts.arn
  protocol  = "email"
  endpoint  = var.team_email_3
}

resource "aws_sns_topic_subscription" "person4_email" {
  topic_arn = aws_sns_topic.sqli_alerts.arn
  protocol  = "email"
  endpoint  = mosomo82us@gmail.com
}

resource "aws_sns_topic_subscription" "person5_email" {
  topic_arn = aws_sns_topic.sqli_alerts.arn
  protocol  = "email"
  endpoint  = var.team_email_5
}

output "sns_topic_arn" {
  value       = aws_sns_topic.sqli_alerts.arn
  description = "ARN to set as SNS_TOPIC_ARN env var in Lambda"
}
