output "aws_region" {
  description = "AWS region used for the deployment"
  value       = var.aws_region
}
output "incident_sns_topic_arn" {
  description = "SNS topic ARN for incident notification"
  value       = aws_sns_topic.incident_alerts.arn
}
output "incident_log_group" {
  description = "Cloudwatch log group for incident investigations"
  value       = aws_cloudwatch_log_group.incident_logs.name
}
output "triage_lambda_name" {
  description = "Incident triage Lambda function"
  value       = aws_lambda_function.lambda_triage.function_name
}
output "s3_detection_rule" {
  description = "EventBridge rule for S3 security config changes"
  value       = aws_cloudwatch_event_rule.s3_config_changes.name
}
