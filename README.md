# AWS Cloud Security Incident Response & Auto-Remediation Platform

An event-driven AWS security automation project that detects potentially insecure Amazon S3 configurations, investigates security findings, classifies risk, records incidents, and automatically remediates selected misconfigurations using Python, Boto3, AWS Lambda, EventBridge, DynamoDB, SNS, and Terraform.

## Project Overview

Cloud security teams need to detect misconfigurations quickly and respond before they become security incidents.

This project implements an automated incident response workflow for Amazon S3 security configuration changes. It monitors selected S3 management API events through AWS CloudTrail and Amazon EventBridge, invokes an AWS Lambda function for investigation, classifies findings by risk level, and stores incident records in DynamoDB.

For eligible MEDIUM-risk findings on a designated test bucket, the Lambda function automatically restores all four S3 Block Public Access settings and verifies the resulting configuration.

Security findings are also delivered through Amazon SNS email notifications.

**Project objective:** Demonstrate practical cloud security monitoring, incident investigation, risk classification, automated containment, and post-remediation verification.

## Architecture

```text
        S3 Configuration Change
                  |
                  v
             AWS CloudTrail
                  |
                  v
             EventBridge
                  |
                  v
          AWS Lambda (Boto3)
                  |
          Investigate S3 Bucket
                  |
          Classify Security Risk
                  |
          +-------+--------+
          |                |
          v                v
      DynamoDB           SNS
   Incident Records   Email Alerts
          |
          v
    Remediation Decision
          |
          v
   Eligible MEDIUM Risk?
          |
          v
   Enable S3 Block Public Access
          |
          v
     Verify Configuration
          |
          v
   Update DynamoDB Incident
          |
          v
     Remediation Result
```

### AWS Services Used

| AWS Service | Purpose |
|---|---|
| Amazon S3 | Test resource and security configuration monitoring |
| AWS CloudTrail | Records S3 management API activity |
| Amazon EventBridge | Detects selected S3 configuration changes and triggers Lambda |
| AWS Lambda | Performs security investigation, risk classification, and remediation |
| AWS IAM | Provides scoped execution permissions |
| Amazon DynamoDB | Stores security incident records and remediation status |
| Amazon SNS | Sends security alert notifications |
| Amazon CloudWatch Logs | Stores Lambda execution logs |
| Terraform | Provisions and manages AWS infrastructure |

## Security Events Monitored

The EventBridge rule monitors these CloudTrail management API events:

- `PutBucketPolicy`
- `PutBucketAcl`
- `PutBucketPublicAccessBlock`
- `DeleteBucketPublicAccessBlock`

When one of these events occurs, Lambda inspects the current bucket configuration.

### Security Investigation

The Lambda function uses Boto3 to inspect:

1. **Bucket policy status:** Checks whether AWS classifies the bucket policy as public.
2. **Bucket ACL:** Identifies grants to the `AllUsers` and `AuthenticatedUsers` groups.
3. **Bucket-level Block Public Access:** Checks all four protection settings.
4. **Inspection errors:** Records errors that prevent a complete security assessment.

### Risk Classification

| Risk Level | Detection Criteria | Response |
|---|---|---|
| HIGH | Potentially public bucket policy or public ACL grants detected | Record incident and send SNS alert |
| MEDIUM | One or more Block Public Access protections disabled, or bucket-level configuration not configured | Record incident and send SNS alert; eligible test-bucket configurations are automatically remediated |
| REVIEW | Security inspection incomplete | Record incident and send SNS alert |
| LOW | All four protections enabled, with no public policy or ACL detected | No incident created |

**Note:** Risk classification identifies potentially insecure configurations. A public-policy classification does not by itself prove that data is publicly reachable; effective access also depends on other AWS controls.

## Automated Remediation

Automated remediation is deliberately restricted to a dedicated test bucket:

`incident-response-test-001`

When the following conditions are satisfied:

- Risk level is MEDIUM.
- The affected bucket matches the designated test bucket.
- The bucket has a readable Block Public Access configuration.
- At least one of the four protection settings is disabled.

Lambda calls the S3 `PutPublicAccessBlock` API to enable all four settings:

```python
s3.put_public_access_block(
    Bucket=bucket,
    PublicAccessBlockConfiguration={
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
)
```

After applying the configuration, Lambda retrieves the settings again using `GetPublicAccessBlock` to verify the result.

The remediation outcome is recorded in DynamoDB:

- `COMPLETED` — All four settings were successfully verified.
- `FAILED` — The remediation operation failed or verification did not confirm all protections.

The incident record also tracks whether its DynamoDB update succeeded.

### Remediation Safeguards

This project follows a conservative remediation strategy:

- Automatic remediation is restricted to one designated test bucket.
- Only eligible MEDIUM-risk findings trigger automatic remediation.
- HIGH-risk public policy and ACL findings are alerted but not automatically modified.
- REVIEW findings are not automatically remediated.
- Remediation is verified by reading the S3 configuration after applying changes.
- IAM permissions restrict the remediation API action to the designated test bucket.

These safeguards help reduce the risk of disrupting legitimate workloads.

## Incident Management with DynamoDB

Each non-LOW finding creates an incident record containing information such as:

| Attribute | Description |
|---|---|
| `incident_id` | Unique incident identifier |
| `bucket` | Affected S3 bucket |
| `event_name` | CloudTrail API event |
| `event_time` | Event timestamp |
| `actor` | Identity associated with the API event |
| `source_ip` | Event source IP address |
| `risk_level` | Classified security risk |
| `finding` | Security investigation result |
| `status` | Incident status |
| `remediation_status` | Remediation outcome |
| `created_at` | Incident creation timestamp |
| `remediated_at` or `remediation_attempted_at` | Remediation timestamp, depending on the deployed code version |

DynamoDB uses on-demand billing for this project.

## Testing and Validation

The project was deployed and tested in AWS Mumbai (`ap-south-1`).

### Automated Remediation Test

A controlled test was performed by disabling only `BlockPublicAcls` on the designated test bucket.

The following sequence was observed:

1. CloudTrail recorded the `PutBucketPublicAccessBlock` API event.
2. EventBridge invoked the Lambda function.
3. Lambda inspected the bucket and classified the finding as MEDIUM.
4. A new incident record was created in DynamoDB.
5. Lambda enabled all four Block Public Access settings.
6. Lambda retrieved the configuration and verified all four settings.
7. DynamoDB was updated with `remediation_status = COMPLETED`.
8. An SNS notification was generated.

### Event Loop Validation

The remediation API call generated another CloudTrail event.

EventBridge invoked Lambda again, and the function inspected the bucket. Because all four protections were now enabled, the second invocation classified the bucket as LOW.

No additional incident or remediation action was created.

### Verified Results

| Test | Expected Result | Outcome |
|---|---|---|
| Disabled Block Public Access setting | MEDIUM classification | Passed |
| Incident creation | DynamoDB record created | Passed |
| Automatic remediation | All four settings enabled | Passed |
| Post-remediation verification | All settings confirmed true | Passed |
| Incident update | Remediation status COMPLETED | Passed |
| SNS notification | Security alert delivered | Passed |
| Remediation-generated event | Classified LOW | Passed |
| Repeated remediation | No unnecessary second remediation | Passed |

## Terraform Deployment

Terraform provisions the AWS infrastructure, including the Lambda execution role and policy, Lambda function, EventBridge rule and target, SNS topic, CloudWatch log group, and DynamoDB table.

### Prerequisites

- AWS account
- AWS CLI configured with appropriate credentials
- Terraform installed
- Python 3.12
- An email address for the SNS subscription

### 1. Clone the Repository

```bash
git clone <https://github.com/aaankeet/aws-incident-response>
cd <aws-incident-response>
```

### 2. Configure AWS Credentials

```bash
aws configure
```

Use an AWS identity with the permissions required to provision the project resources.

### 3. Initialize Terraform

```bash
cd terraform
terraform init
```

### 4. Validate Configuration

```bash
terraform fmt
terraform validate
terraform plan
```

### 5. Deploy Infrastructure

```bash
terraform apply
```

Review the execution plan before approving deployment.

### 6. Confirm SNS Email Subscription

Check your inbox for the SNS subscription confirmation email and confirm the subscription.

### 7. Test the Deployment

Use a dedicated test bucket. Follow the controlled remediation test described above and inspect:

- Lambda execution logs in CloudWatch.
- Incident records in DynamoDB.
- S3 Block Public Access settings.
- SNS email notifications.

## Repository Structure

```text
aws-incident-response/
│
├── src/
│   ├── __init__.py
│   └── triage.py
│
├── terraform/
│   ├── providers.tf
│   ├── variables.tf
│   └── main.tf
│
├── test_triage.py
│
└── README.md
```

*Adjust the structure above if your actual repository contains additional or differently named Terraform files.*

## IAM Security and Least Privilege

The Lambda execution role uses an IAM policy that grants only the API actions needed for the implemented workflow.

Examples include:

- S3 inspection permissions for bucket policy status, ACLs, and Block Public Access configuration.
- `s3:PutBucketPublicAccessBlock` scoped to the designated test bucket.
- DynamoDB `PutItem` and `UpdateItem` scoped to the incident table.
- SNS `Publish` scoped to the notification topic.
- CloudWatch Logs permissions scoped to the Lambda log group.

The remediation permission is intentionally restricted to the test bucket rather than all S3 buckets.

## Cost Considerations

This project was designed as a low-usage learning lab.

Cost-conscious choices include:

- DynamoDB on-demand billing.
- Lambda with 128 MB memory and a 30-second timeout.
- No S3 data-event logging.
- No paid GuardDuty, AWS Config, or Security Hub dependencies.
- Limited EventBridge event patterns.

Actual charges depend on AWS account usage, region, service pricing, and free-tier eligibility. Monitor AWS billing and remove resources when the lab is no longer needed.

## Current Scope and Limitations

This is a portfolio lab, not a complete enterprise security operations platform.

Current limitations include:

- Monitoring is limited to the selected S3 management API events.
- The investigation reads the bucket's current configuration, which may differ from its state at the original event timestamp.
- The inspection does not cover every possible S3 access path, such as access points, organization-level controls, or all cross-account permission combinations.
- Automatic remediation is limited to one designated test bucket and eligible MEDIUM-risk findings.
- HIGH-risk policy and ACL findings require further investigation and manual remediation.
- Incident lifecycle management, approval workflows, and automated escalation are not implemented.
- The project does not replace AWS Security Hub, GuardDuty, or a production SIEM.

## Skills Demonstrated

- AWS Cloud Security
- Security Monitoring and Incident Response
- AWS CloudTrail and EventBridge
- AWS Lambda and Python
- Boto3 SDK
- S3 Security and Block Public Access
- IAM Least Privilege
- DynamoDB
- SNS Alerting
- CloudWatch Logs
- Terraform / Infrastructure as Code
- Automated Remediation and Verification

## Author

**Cloud Security Engineering Portfolio Project**

This project was built as a hands-on exercise to develop practical AWS cloud security engineering skills, with an emphasis on event-driven detection, investigation, and controlled automated remediation.
