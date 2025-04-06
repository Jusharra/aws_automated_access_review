"""
AWS Access Review Lambda function for automated security auditing.
This lambda collects security findings from various AWS services and generates a report.

Version: 1.0.0
"""

import json
import boto3
import os
import datetime

# Import modules for functionality
from modules.iam_findings import collect_iam_findings
from modules.scp_findings import collect_scp_findings
from modules.securityhub_findings import collect_securityhub_findings
from modules.access_analyzer_findings import collect_access_analyzer_findings
from modules.cloudtrail_findings import collect_cloudtrail_findings
from modules.narrative import generate_ai_narrative
from modules.reporting import generate_csv_report, upload_to_s3
from modules.email_utils import send_email_with_attachment, verify_email_for_ses


def handler(event, context):
    """
    Main handler for the AWS Access Review Lambda function.
    Collects security findings from various AWS services and generates a report.
    """
    print("Starting AWS Access Review")

    # Check if this is a forced real execution
    force_real_execution = event.get("force_real_execution", False)
    if force_real_execution:
        print("Forcing real execution with email delivery")

    # Get environment variables
    report_bucket = os.environ["REPORT_BUCKET"]

    # Use recipient email from event if provided, otherwise use environment variable
    recipient_email = event.get("recipient_email", os.environ["RECIPIENT_EMAIL"])
    print(f"Will send report to: {recipient_email}")

    # Initialize AWS clients
    iam = boto3.client("iam")
    try:
        org = boto3.client("organizations")
    except Exception as e:
        error_msg = str(e)
        print(f"Warning: Unable to initialize Organizations client: {error_msg}")
        org = None

    try:
        securityhub = boto3.client("securityhub")
    except Exception as e:
        error_msg = str(e)
        print(f"Warning: Unable to initialize Security Hub client: {error_msg}")
        securityhub = None

    try:
        access_analyzer = boto3.client("accessanalyzer")
    except Exception as e:
        error_msg = str(e)
        print(f"Warning: Unable to initialize Access Analyzer client: {error_msg}")
        access_analyzer = None

    cloudtrail = boto3.client("cloudtrail")
    bedrock = boto3.client("bedrock-runtime")
    s3 = boto3.client("s3")
    ses = boto3.client("ses")

    # Verify the recipient email in SES if needed
    try:
        verify_email_for_ses(ses, recipient_email)
    except Exception as e:
        error_msg = str(e)
        print(f"Warning: Could not verify email in SES: {error_msg}")

    # Collect findings
    findings = []

    try:
        # Collect IAM findings
        iam_findings = collect_iam_findings(iam)
        findings.extend(iam_findings)

        # Collect SCP findings if Organizations is available
        if org:
            scp_findings = collect_scp_findings(org)
            findings.extend(scp_findings)

        # Collect Security Hub findings if available
        if securityhub:
            securityhub_findings = collect_securityhub_findings(securityhub)
            findings.extend(securityhub_findings)

        # Collect IAM Access Analyzer findings if available
        if access_analyzer:
            access_analyzer_findings = collect_access_analyzer_findings(access_analyzer)
            findings.extend(access_analyzer_findings)

        # Collect CloudTrail findings
        cloudtrail_findings = collect_cloudtrail_findings(cloudtrail, s3)
        findings.extend(cloudtrail_findings)

        # Generate CSV report
        csv_content, csv_filename = generate_csv_report(findings)

        # Upload CSV to S3
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        csv_key = f"reports/aws-access-review-{timestamp}.csv"
        upload_to_s3(s3, report_bucket, csv_content, csv_key)

        # Generate AI narrative using Bedrock
        narrative = generate_ai_narrative(bedrock, findings)

        # Send email with CSV attachment
        send_email_with_attachment(
            ses, recipient_email, narrative, csv_content, csv_filename
        )

        return {
            "statusCode": 200,
            "body": json.dumps("AWS Access Review completed successfully"),
        }

    except Exception as e:
        error_msg = str(e)
        print(f"Error in AWS Access Review: {error_msg}")
        return {"statusCode": 500, "body": json.dumps(f"Error: {error_msg}")}
