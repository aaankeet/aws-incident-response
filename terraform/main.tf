# Identify the AWS account Terraform is deploying to
data "aws_caller_identity" "current" {}

# SNS topic for incident notification
resource "aws_sns_topic" "incident_alerts" {
  name = "${var.project_name}-alerts"
}

# Cloudwatch log group for incident triage
resource "aws_cloudwatch_log_group" "incident_logs" {
  name              = "/aws/lambda/${var.project_name}-triage"
  retention_in_days = 7
}

# Lambda execution role
resource "aws_iam_role" "incident_triage_role" {
  name = "${var.project_name}-triage-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Action = "sts:AssumeRole",
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Permission required by the lambda to investigate
# Least-privelege permission required by lambda for investigation
resource "aws_iam_role_policy" "incident_triage_policy" {
  name = "${var.project_name}-triage-policy"
  role = aws_iam_role.incident_triage_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketAcl",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "arn:aws:s3:::*"
      },
      {
        Effect   = "Allow",
        Action   = "sns:Publish",
        Resource = aws_sns_topic.incident_alerts.arn
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.incident_logs.arn}:*"
      },
      {
        Sid      = "DynamoDBIncidentWrite"
        Effect   = "Allow",
        Action   = "dynamodb:PutItem",
        Resource = aws_dynamodb_table.security_incidents.arn
      },
      {
        Sid = "RemediateTestBucketPublicAccess",
        Effect = "Allow",
        Action = "s3:PutPublicAccessBlock"
        Resource = [
          "arn:aws:s3:::incident-response-test-001"
        ]
      }
    ]
  })

}

# package python source code
data "archive_file" "triage_script_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/triage.py"
  output_path = "${path.module}/triage.zip"
}

# deploy lambda function
resource "aws_lambda_function" "lambda_triage" {
  function_name    = "${var.project_name}-triage-function"
  role             = aws_iam_role.incident_triage_role.arn
  runtime          = "python3.12"
  handler          = "triage.lambda_handler"
  filename         = data.archive_file.triage_script_zip.output_path
  source_code_hash = data.archive_file.triage_script_zip.output_base64sha256

  timeout     = 30
  memory_size = 128

  # set the lambda environment variable
  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.incident_alerts.arn
      INCIDENTS_TABLE = aws_dynamodb_table.security_incidents.name
    }
  }
  depends_on = [
    aws_iam_role_policy.incident_triage_policy
  ]
  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.incident_logs.name
  }
}

# EventBridge rule for potentially risky S3 configuration changes
resource "aws_cloudwatch_event_rule" "s3_config_changes" {
  name        = "${var.project_name}-s3-config-changes"
  description = "Detect S3 bucket security configuration changes"

  event_pattern = jsonencode({
    source = ["aws.s3"]
    "detail-type" = [
      "AWS API Call via CloudTrail"
    ]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "PutBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock"
      ]
    }
  })
}

# Connect EventBridge to Lambda
resource "aws_cloudwatch_event_target" "s3_triage_target" {
  rule      = aws_cloudwatch_event_rule.s3_config_changes.name
  target_id = "S3TriageLambda"
  arn       = aws_lambda_function.lambda_triage.arn
}

# Allow EventBridge to invoke Lambda function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_triage.function_name
  principal     = "events.amazonaws.com"

  source_arn = aws_cloudwatch_event_rule.s3_config_changes.arn
}
