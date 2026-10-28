# ---------- ENABLE CLOUDTRAIL ---------- 
# Generates a random suffix so the CloudTrail log bucket name is globally unique.
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Stores CloudTrail logs for S3 object-level and management events.
resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "s3-public-access-trail-bucket-${random_id.bucket_suffix.hex}"
  force_destroy = true
}

# Allows CloudTrail to verify the log bucket and deliver log objects to it.
resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.trail_bucket.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Records S3 API activity in the configured log bucket for detecting access changes.
resource "aws_cloudtrail" "s3_trail" {
  name                          = "s3-public-access-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.bucket
  enable_logging                = true
  include_global_service_events = false
  is_multi_region_trail         = false
  depends_on                    = [aws_s3_bucket_policy.trail_bucket_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
}

# ---------- CREATE SNS TOPIC AND SUBSCRIPTION ----------

# Receives notifications when the Lambda function detects potentially public access.
resource "aws_sns_topic" "s3_public_alerts" {
  name = "s3-public-access-alerts"
}

# Sends alerts from the topic to the configured email address.
resource "aws_sns_topic_subscription" "email_subscription" {
  topic_arn = aws_sns_topic.s3_public_alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ---------- CREATE IAM ROLE FOR LAMBDA ----------
# Grants AWS Lambda permission to assume the execution role.
resource "aws_iam_role" "lambda_role" {
  name = "s3-public-alert-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Allows the function to inspect S3 buckets, publish alerts, and write CloudWatch logs.
resource "aws_iam_policy" "lambda_policy" {
  name        = "s3-public-access-lambda-policy"
  description = "Lambda permissions to check S3 buckets and send SNS alerts"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPublicAccessBlock",
          "s3:ListAllMyBuckets"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.s3_public_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attaches the S3, SNS, and logging permissions to the Lambda execution role.
resource "aws_iam_role_policy_attachment" "lambda_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# ---------- CREATE THE LAMBDA FUNCTION ----------
# Packages the Python handler into the ZIP file deployed to Lambda.
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "lambda_function.py"
  output_path = "lambda_function.zip"
}

# Runs the S3 public-access checks and publishes findings to the SNS topic.
resource "aws_lambda_function" "s3_public_alert" {
  function_name = "s3-security-checker"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  timeout = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.s3_public_alerts.arn
    }
  }
}

# ---------- CREATE EVENTBRIDGE RULE ----------
# Matches CloudTrail events for S3 bucket policy, ACL, and public-access-block changes.
resource "aws_cloudwatch_event_rule" "s3_events_rule" {
  name        = "s3-public-access-rule"
  description = "Trigger Lambda for S3 bucket public access changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
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

# Routes matching S3 change events to the public-access detection Lambda.
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.s3_events_rule.name
  target_id = "LambdaTarget"
  arn       = aws_lambda_function.s3_public_alert.arn
}

# Permits EventBridge to invoke the Lambda function when the rule matches.
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_public_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_events_rule.arn
}



