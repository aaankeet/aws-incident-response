import os
import json
import boto3
import logging
import uuid
from datetime import datetime, timezone
from botocore.exceptions import ClientError


logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client("s3")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
INCIDENTS_TABLE = os.environ.get("INCIDENTS_TABLE")

# S3 ACL Group Identifiers
PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

# risk classification function
def classify_risk(findings):

    has_public_policy = findings["public_policy"] is True
    has_public_acl = len(findings["public_acl_grants"]) > 0

    public_access_block = findings["public_access_block"]

    if has_public_policy or has_public_acl:
        return (
            "HIGH",
            "Potential public S3 access configuration detected"
        )
    if findings["inspection_errors"]:
        return (
            "REVIEW",
            "Bucket inspection was incomplete"
        )
    if public_access_block == "Not configured":
        return (
            "MEDIUM",
            "Bucket-level Public Access Block is not configured"
        )
    if isinstance(public_access_block, dict):
        settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        if not all(public_access_block.get(setting) is True for setting in settings):
            return (
                "MEDIUM",
                "One or more S3 Block Public Access protections are disabled"
            )

    return (
        "LOW",
        "All S3 Block Public Access protections are enabled; no public policy or ACL detected"
    )

# Record Incidents
def record_incidents(findings):
    if not INCIDENTS_TABLE:
        logger.error("INCIDENTS_TABLE environment variable is missing")
        raise ValueError("INCIDENTS_TABLE is not configured")

    table = dynamodb.Table(INCIDENTS_TABLE)
    incidents = {
        "incident_id": str(uuid.uuid4()),
        "bucket": findings["bucket"],
        "event_name": findings["event_name"] or "Unknown",
        "event_time": findings["event_time"] or "Unknown",
        "actor": findings["actor"],
        "source_ip": findings["source_ip"],
        "risk_level": findings["risk_level"],
        "finding": findings["finding"],
        "status": "OPEN",
        "remediation_status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "details": findings
    }

    # Put items in the table
    table.put_item(Item=incidents)
    logger.info("Incident saved to DynamoDB. Incident ID: %s", incidents["incident_id"])
    return incidents["incident_id"]


# Lambda handler function
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
            findings["public_access_block"] = "Not configured"
        else:
            findings["inspection_errors"].append(f"Public access block inspection: {code}")

    # classify findings
    findings["risk_level"], findings["finding"] = classify_risk(findings)

    logger.info("S3 investigation result: %s", json.dumps(findings))

    incident_id = None
    if findings["risk_level"] != "LOW":
        # Get the incident ID
        incident_id = record_incidents(findings)

    # notify through SNS
    if findings["risk_level"] != "LOW" and SNS_TOPIC_ARN:
        notification = {
            "incident_id": incident_id,
            "findings": findings
        }

        sns.publish(
            TopicArn = SNS_TOPIC_ARN,
            Subject = f"S3 Alert: {findings['risk_level']}",
            Message = json.dumps(notification, indent=2, default=str)
        )
    return findings
