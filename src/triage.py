import os
import json
import boto3
import logging

from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# S3 ACL Group Identifiers
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def lambda_handler(event,context ):
    detail = event.get('detail',{})
    request = detail.get("requestParameters",{}) or {}

    # Get bucket name from event
    bucket = request.get("bucketName")

    if not bucket:
        logger.warning("Could not identify bucket name in events")
        return {"status":"skipped", "reason": "Missing bucket name"}

    findings = {
        "bucket": bucket,
        "event_name": detail.get("eventName"),
        "event_time": detail.get("eventTime"),
        "actor": detail.get("userIdentity",{}).get("arn","Unknown"),
        "source_ip": detail.get("sourceIPAddress","Unknown"),
        "public_policy": "unknown",
        "public_acl_grants": [],
        "public_access_block": "unknown",
        "inspection_errors": []
    }

    # check bucket policy status
    try:
        response = s3.get_bucket_policy_status(Bucket=bucket)
        findings["public_policy"] = response["PolicyStatus"]["IsPublic"]

    except ClientError as error:
        code = error.response["Error"]["Code"]

        if code == "NoSuchBucketPolicy":
            findings["public_policy"] = False
        else:
            findings["inspection_errors"].append(f"Policy inspection: {code}")

    # check bucket ACL for public grants
    try:
        response = s3.get_bucket_acl(Bucket=bucket)

        for grant in response.get("Grants",[]):
            grantee = grant.get("Grantee",{})
            uri = grantee.get("URI")

            if uri in PUBLIC_GROUPS:
                findings["public_acl_grants"].append({
                    "permission": grant.get("Permission"),
                    "grantee": uri
                })

    except ClientError as error:
        code = error.response["Error"]["Code"]
        findings["inspection_errors"].append(f"ACL inspection: {code}")

    # check S3 block public access
    try:
        response = s3.get_public_access_block(Bucket=bucket)
        findings["public_access_block"] = response["PublicAccessBlockConfiguration"]

    except ClientError as error:
        code = error.response["Error"]["Code"]

        if code == "NoSuchPublicAccessBlockConfiguration":
            findings["public_access_block"] = "Not Configured"
        else:
            findings["inspection_errors"].append(f"Public access block inspection: {code}")

    # classify the findings
    has_public_policy = findings["public_policy"] is True
    has_public_acl = len(findings["public_acl_grants"]) > 0
    public_access_block = findings["public_access_block"]

    if has_public_policy or has_public_acl:
        findings["risk_level"] = "HIGH"
        findings["finding"] = "Potential public S3 access configuration detected"

    elif findings["inspection_errors"]:
        findings["risk_level"] = "REVIEW"
        findings["finding"] = "Bucket inspection was incomplete"

    elif findings["public_access_block"] == "Not Configured":
        findings["risk_level"] = "MEDIUM"
        findings["finding"] = "Bucket-level Public Access Block is not configured"

    elif isinstance(public_access_block, dict) and not all([
        public_access_block.get("BlockPublicAcls") is True,
          public_access_block.get("IgnorePublicAcls") is True,
          public_access_block.get("BlockPublicPolicy") is True,
          public_access_block.get("RestrictPublicBuckets") is True,
    ]):
        findings["risk_level"] = "MEDIUM"
        findings["finding"] = "One or more S3 Block Public Access protections are disabled"

    else:
        findings["risk_level"] = "LOW"
        findings["finding"] = "All S3 Block Public Access protections are enabled; no public policy or ACL detected"

    logger.info("S3 investigation result: %s", json.dumps(findings))

    # notify only when the investigation identifies something to review
    if findings["risk_level"] != "LOW":
        sns.publish(
            TopicArn = SNS_TOPIC_ARN,
            Subject = f"S3 Alert: {findings['risk_level']}",
            Message = json.dumps(findings, indent=2, default=str)
        )
    return findings
