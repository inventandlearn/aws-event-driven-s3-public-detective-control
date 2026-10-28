import json
import boto3
import os
from dateutil import parser

s3 = boto3.client('s3')
sns = boto3.client('sns')


SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
PUBLIC_GROUPS = [
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
]

def lambda_handler(event, context):
    """Inspect an S3 configuration-change event and alert on public access findings."""
    detail = event["detail"]

    # ---- Extract Info ----
    bucket_name = detail["requestParameters"]["bucketName"]
    account_id = detail["userIdentity"]["accountId"]
    region = detail["awsRegion"]
    actor = detail["userIdentity"].get("arn", "Unknown")
    event_name = detail["eventName"]
    event_time = detail["eventTime"]
    readable_time = parser.isoparse(event_time).strftime("%Y-%m-%d %H:%M:%S UTC")
    findings = []

    # ---- Extract Human Name From ARN ----
    if "/" in actor:
        actor_name = actor.split("/")[-1]
    else:
        actor_name = ""

    # ---- Check Public Access Block ----
    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)
        pab_config = pab["PublicAccessBlockConfiguration"]
        if not all(pab_config.values()):
            findings.append("Public Access Block is DISABLED or partially disabled")

    except Exception as e:
        print(f"PAB check error: {e}")
   

    # ---- Check Bucket Policy Status ----
    try:
        policy_response = s3.get_bucket_policy_status(Bucket=bucket_name)
        policy_status = policy_response["PolicyStatus"]["IsPublic"]

        if policy_status:
            findings.append("Bucket policy allows public access")

    except Exception as e:
        print(f"Bucket policy check error: {e}")

    
    # ----  CHECK BUCKET ACL ----

    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in acl["Grants"]:
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")

            if uri in PUBLIC_GROUPS:
                findings.append("Bucket ACL grants public read/write access")

    except Exception as e:
        print(f"ACL check error: {e}")

    # ---- SNS Alert  ----
    if findings:
        findings_text = "\n".join([f"- {f}" for f in findings])
        message = f"""Hello {actor_name},
SECURITY ALERT: Public S3 Bucket Detected

WHAT HAPPENED?
A configuration change was made that may expose an S3 bucket to the public internet.

AFFECTED RESOURCE
Bucket Name: {bucket_name}
AWS Account ID: {account_id}
Region: {region}

WHO PERFORMED THIS ACTION?
Identity: {actor}

WHEN DID IT HAPPEN?
Time: {readable_time}

TRIGGER EVENT 
Event Name: {event_name}

SECURITY FINDINGS
{findings_text}
"""

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="Security Alert: Public S3 Bucket Detected",
            Message=message
        )
        
        