import json
import boto3
import os
import csv
import io
import datetime
import email.mime.multipart
import email.mime.text
import email.mime.application


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
        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(
            csv_buffer,
            fieldnames=[
                "id",
                "category",
                "severity",
                "resource_type",
                "resource_id",
                "description",
                "recommendation",
                "compliance",
                "detection_date",
            ],
        )
        csv_writer.writeheader()
        for finding in findings:
            csv_writer.writerow(finding)

        # Upload CSV to S3
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        csv_key = f"reports/aws-access-review-{timestamp}.csv"
        s3.put_object(
            Bucket=report_bucket,
            Key=csv_key,
            Body=csv_buffer.getvalue(),
            ContentType="text/csv"
        )

        # Generate AI narrative using Bedrock
        narrative = generate_ai_narrative(bedrock, findings)

        # Send email with CSV attachment
        send_email_with_attachment(
            ses,
            recipient_email,
            narrative,
            csv_buffer.getvalue(),
            f"aws-access-review-{timestamp}.csv",
        )

        return {
            "statusCode": 200,
            "body": json.dumps("AWS Access Review completed successfully")
        }

    except Exception as e:
        error_msg = str(e)
        print(f"Error in AWS Access Review: {error_msg}")
        return {
            "statusCode": 500,
            "body": json.dumps(f"Error: {error_msg}")
        }


def collect_iam_findings(iam):
    """
    Collect IAM-related security findings.
    Looks for:
    - Users with console access but no MFA
    - Users with old access keys
    - Users with wide permissions (admin policies)
    - Unused credentials
    """
    findings = []
    print("Collecting IAM findings...")

    try:
        # Get all IAM users
        response = iam.list_users()
        users = response["Users"]
        while response.get("IsTruncated", False):
            response = iam.list_users(Marker=response["Marker"])
            users.extend(response["Users"])

        # Check each user for security issues
        for user in users:
            username = user["UserName"]

            # Check if user has console access but no MFA
            login_profile_exists = False
            try:
                iam.get_login_profile(UserName=username)
                login_profile_exists = True
            except iam.exceptions.NoSuchEntityException:
                login_profile_exists = False

            if login_profile_exists:
                # Check MFA devices
                mfa_response = iam.list_mfa_devices(UserName=username)
                if not mfa_response["MFADevices"]:
                    findings.append({
                        "id": f"IAM-001-{username}",
                        "category": "IAM",
                        "severity": "High",
                        "resource_type": "IAM User",
                        "resource_id": username,
                        "description": (
                            f"User {username} has console access but no MFA enabled"
                        ),
                        "recommendation": "Enable MFA for all users with console access",
                        "compliance": "CIS 1.2, AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

            # Check for access keys and their age
            keys_response = iam.list_access_keys(UserName=username)
            for key in keys_response["AccessKeyMetadata"]:
                key_id = key["AccessKeyId"]
                key_created = key["CreateDate"]

                # Check key age
                key_age_days = (
                    datetime.datetime.now(datetime.timezone.utc) - key_created
                ).days

                if key_age_days > 90:
                    findings.append({
                        "id": f"IAM-002-{key_id}",
                        "category": "IAM",
                        "severity": "Medium",
                        "resource_type": "IAM Access Key",
                        "resource_id": f"{username}/{key_id}",
                        "description": (
                            f"Access key {key_id} for user {username} is "
                            f"{key_age_days} days old"
                        ),
                        "recommendation": "Rotate access keys at least every 90 days",
                        "compliance": "CIS 1.4, AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

            # Check for wide permissions (admin access)
            attached_policies = iam.list_attached_user_policies(UserName=username)[
                "AttachedPolicies"
            ]
            for policy in attached_policies:
                if (
                    "admin" in policy["PolicyName"].lower()
                    or "administrator" in policy["PolicyName"].lower()
                ):
                    findings.append({
                        "id": f"IAM-003-{username}",
                        "category": "IAM",
                        "severity": "Medium",
                        "resource_type": "IAM User",
                        "resource_id": username,
                        "description": (
                            f'User {username} has potentially wide privileges via '
                            f'policy {policy["PolicyName"]}'
                        ),
                        "recommendation": "Apply least privilege principle to IAM users",
                        "compliance": "CIS 1.16, AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

        # Check for unused roles
        response = iam.list_roles()
        roles = response["Roles"]
        while response.get("IsTruncated", False):
            response = iam.list_roles(Marker=response["Marker"])
            roles.extend(response["Roles"])

        for role in roles:
            role_name = role["RoleName"]
            if (
                "service-role/" not in role["Path"]
                and not role_name.startswith("AWSServiceRole")
            ):
                last_used_response = (
                    iam.get_role(RoleName=role_name)
                    .get("Role", {})
                    .get("RoleLastUsed", {})
                )
                if "LastUsedDate" not in last_used_response:
                    findings.append({
                        "id": f"IAM-004-{role_name}",
                        "category": "IAM",
                        "severity": "Low",
                        "resource_type": "IAM Role",
                        "resource_id": role_name,
                        "description": f"Role {role_name} appears to be unused",
                        "recommendation": (
                            "Consider removing unused roles to reduce attack surface"
                        ),
                        "compliance": "AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

        # Check password policy
        try:
            password_policy = iam.get_account_password_policy()["PasswordPolicy"]
            if (
                not password_policy.get("RequireUppercaseCharacters", False)
                or not password_policy.get("RequireLowercaseCharacters", False)
                or not password_policy.get("RequireSymbols", False)
                or not password_policy.get("RequireNumbers", False)
                or password_policy.get("MinimumPasswordLength", 0) < 14
            ):
                findings.append({
                    "id": "IAM-005",
                    "category": "IAM",
                    "severity": "Medium",
                    "resource_type": "IAM Password Policy",
                    "resource_id": "account-password-policy",
                    "description": (
                        "IAM password policy does not meet security best practices"
                    ),
                    "recommendation": (
                        "Configure a strong password policy requiring at least 14 "
                        "characters with a mix of character types"
                    ),
                    "compliance": "CIS 1.5-1.11, AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat(),
                })
        except iam.exceptions.NoSuchEntityException:
            findings.append({
                "id": "IAM-006",
                "category": "IAM",
                "severity": "High",
                "resource_type": "IAM Password Policy",
                "resource_id": "account-password-policy",
                "description": "No IAM password policy is set for the account",
                "recommendation": "Configure a strong password policy",
                "compliance": "CIS 1.5-1.11, AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat(),
            })

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting IAM findings: {error_msg}")
        findings.append({
            "id": "IAM-ERROR",
            "category": "IAM",
            "severity": "Medium",
            "resource_type": "IAM Service",
            "resource_id": "error",
            "description": f"Error collecting IAM findings: {error_msg}",
            "recommendation": (
                "Check Lambda execution role permissions for IAM ReadOnly access"
            ),
            "compliance": "N/A",
            "detection_date": datetime.datetime.now().isoformat(),
        })

    print(f"Collected {len(findings)} IAM findings")
    return findings


def collect_scp_findings(org):
    """
    Collect SCP-related security findings.
    Analyzes Service Control Policies for potential security gaps.
    """
    findings = []
    print("Collecting AWS Organizations SCP findings...")

    try:
        # Check if Organizations is in use
        organization = org.describe_organization().get("Organization", {})

        if not organization:
            findings.append({
                "id": "SCP-NOT-USED",
                "category": "SCP",
                "severity": "Informational",
                "resource_type": "AWS Organizations",
                "resource_id": "none",
                "description": (
                    "AWS Organizations is not being used or the Lambda role lacks "
                    "permissions"
                ),
                "recommendation": (
                    "Consider using AWS Organizations with SCPs to enforce security "
                    "guardrails"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat(),
            })
            return findings

        # Get organization roots
        roots = org.list_roots().get("Roots", [])
        if not roots:
            return findings

        # List all policies in the organization
        paginator = org.get_paginator("list_policies")
        policy_pages = paginator.paginate(Filter="SERVICE_CONTROL_POLICY")

        policies = []
        for page in policy_pages:
            policies.extend(page.get("Policies", []))

        # If there are no SCPs (beyond the default FullAWSAccess), flag it
        if len(policies) <= 1:
            findings.append({
                "id": "SCP-001",
                "category": "SCP",
                "severity": "Medium",
                "resource_type": "Service Control Policy",
                "resource_id": "none",
                "description": "No custom SCPs detected in the organization",
                "recommendation": (
                    "Implement SCPs to enforce security guardrails across the "
                    "organization"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat(),
            })

        # Analyze each policy
        for policy in policies:
            policy_id = policy["Id"]
            policy_name = policy["Name"]

            # Skip the default FullAWSAccess policy
            if policy_name == "FullAWSAccess":
                continue

            # Get detailed policy content
            policy_detail = org.describe_policy(PolicyId=policy_id)
            policy_content = policy_detail.get("Policy", {}).get("Content", "{}")

            # Parse the policy content as JSON
            try:
                policy_doc = json.loads(policy_content)
                statements = policy_doc.get("Statement", [])

                # Check for common security best practices in SCPs
                has_deny_root = False
                has_security_services = False

                for statement in statements:
                    action = statement.get("Action", [])
                    if not isinstance(action, list):
                        action = [action]

                    # Check for root user restrictions
                    if (
                        "aws:PrincipalArn" in json.dumps(statement)
                        and "root" in json.dumps(statement).lower()
                    ):
                        has_deny_root = True

                    # Check for security services protections
                    if any(
                        service in json.dumps(statement).lower()
                        for service in [
                            "cloudtrail",
                            "config",
                            "guardduty",
                            "securityhub",
                            "macie",
                            "iam",
                        ]
                    ):
                        has_security_services = True

                # Add findings based on policy analysis
                if not has_deny_root:
                    findings.append({
                        "id": f"SCP-ROOT-{policy_id[-6:]}",
                        "category": "SCP",
                        "severity": "Medium",
                        "resource_type": "Service Control Policy",
                        "resource_id": policy_name,
                        "description": (
                            f'SCP "{policy_name}" does not appear to restrict root user '
                            "activities"
                        ),
                        "recommendation": (
                            "Add statements to deny actions for root users in member "
                            "accounts"
                        ),
                        "compliance": "AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

                if not has_security_services:
                    findings.append({
                        "id": f"SCP-SECURITY-{policy_id[-6:]}",
                        "category": "SCP",
                        "severity": "Low",
                        "resource_type": "Service Control Policy",
                        "resource_id": policy_name,
                        "description": (
                            f'SCP "{policy_name}" does not appear to protect security '
                            "services"
                        ),
                        "recommendation": (
                            "Add statements to prevent disabling of security services"
                        ),
                        "compliance": "AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

            except json.JSONDecodeError:
                findings.append({
                    "id": f"SCP-FORMAT-{policy_id[-6:]}",
                    "category": "SCP",
                    "severity": "Low",
                    "resource_type": "Service Control Policy",
                    "resource_id": policy_name,
                    "description": f'SCP "{policy_name}" has invalid JSON format',
                    "recommendation": "Review and correct the SCP JSON format",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat(),
                })

        # If we've analyzed SCPs but found no issues, add a positive note
        if policies and len(findings) == 0:
            findings.append({
                "id": "SCP-POSITIVE-001",
                "category": "SCP",
                "severity": "Informational",
                "resource_type": "Service Control Policy",
                "resource_id": "organization",
                "description": "Organization SCPs follow security best practices",
                "recommendation": (
                    "Continue to maintain SCPs in line with evolving security needs"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat(),
            })

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting SCP findings: {error_msg}")
        findings.append({
            "id": "SCP-ERROR",
            "category": "SCP",
            "severity": "Medium",
            "resource_type": "Organizations Service",
            "resource_id": "error",
            "description": f"Error analyzing SCPs: {error_msg}",
            "recommendation": (
                "Check Lambda execution role permissions for Organizations ReadOnly "
                "access"
            ),
            "compliance": "N/A",
            "detection_date": datetime.datetime.now().isoformat(),
        })

    print(f"Collected {len(findings)} SCP findings")
    return findings


def collect_securityhub_findings(securityhub):
    """
    Collect IAM-related findings from Security Hub.
    Focuses on high and critical findings related to identity and access management.
    """
    findings = []
    print("Collecting AWS Security Hub findings...")

    try:
        # Check if Security Hub is enabled by retrieving enabled standards
        enabled_standards = securityhub.get_enabled_standards().get(
            "StandardsSubscriptions", []
        )

        if not enabled_standards:
            findings.append({
                "id": "SECHUB-NOT-ENABLED",
                "category": "SecurityHub",
                "severity": "High",
                "resource_type": "AWS Security Hub",
                "resource_id": "none",
                "description": "Security Hub is not enabled in this account",
                "recommendation": (
                    "Enable Security Hub and at least the CIS AWS Foundations standard"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat()
            })
            return findings

        # Get findings paginator
        paginator = securityhub.get_paginator("get_findings")

        # Filter for IAM-related findings with high/critical severity
        filters = {
            "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            "SeverityLabel": [
                {"Value": "HIGH", "Comparison": "EQUALS"},
                {"Value": "CRITICAL", "Comparison": "EQUALS"}
            ],
            "ResourceType": [{"Value": "AwsIam", "Comparison": "PREFIX"}]
        }

        # Get findings pages
        findings_pages = paginator.paginate(Filters=filters)

        # Process findings
        for page in findings_pages:
            for finding in page.get("Findings", [])[:50]:  # Limit to first 50
                findings.append({
                    "id": finding.get("Id", "")[-12:],
                    "category": "SecurityHub",
                    "severity": finding.get("Severity", {}).get("Label", "MEDIUM"),
                    "resource_type": finding.get("Resources", [{}])[0].get("Type", ""),
                    "resource_id": finding.get("Resources", [{}])[0].get("Id", ""),
                    "description": finding.get("Description", ""),
                    "recommendation": finding.get("Remediation", {}).get(
                        "Recommendation", {}
                    ).get("Text", "Review finding in Security Hub console"),
                    "compliance": finding.get("Compliance", {}).get("Status", ""),
                    "detection_date": finding.get("FirstObservedAt", "")
                })

        # If no findings detected, add a positive note
        if not findings:
            findings.append({
                "id": "SECHUB-POSITIVE-001",
                "category": "SecurityHub",
                "severity": "Informational",
                "resource_type": "AWS Security Hub",
                "resource_id": "none",
                "description": "No high/critical IAM-related findings detected",
                "recommendation": "Continue monitoring Security Hub findings",
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat()
            })

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting Security Hub findings: {error_msg}")
        findings.append({
            "id": "SECHUB-ERROR",
            "category": "SecurityHub",
            "severity": "Medium",
            "resource_type": "AWS Security Hub",
            "resource_id": "error",
            "description": f"Error collecting findings: {error_msg}",
            "recommendation": "Check Lambda role permissions for Security Hub",
            "compliance": "N/A",
            "detection_date": datetime.datetime.now().isoformat()
        })

    print(f"Collected {len(findings)} Security Hub findings")
    return findings


def collect_access_analyzer_findings(access_analyzer):
    """
    Collect findings from IAM Access Analyzer.
    Identifies external access to resources that should be private.
    """
    findings = []
    print("Collecting IAM Access Analyzer findings...")

    try:
        # Get all analyzers in the account
        analyzers_response = access_analyzer.list_analyzers(type="ACCOUNT")
        analyzers = analyzers_response.get("analyzers", [])

        if not analyzers:
            findings.append({
                "id": "AA-001",
                "category": "Access Analyzer",
                "severity": "Medium",
                "resource_type": "IAM Access Analyzer",
                "resource_id": "none",
                "description": "No IAM Access Analyzer is configured for this account",
                "recommendation": (
                    "Enable IAM Access Analyzer to detect resources that are shared "
                    "externally"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat(),
            })
            return findings

        # For each analyzer, get active findings
        for analyzer in analyzers:
            analyzer_arn = analyzer["arn"]
            analyzer_name = analyzer["name"]

            # List active findings for this analyzer
            list_findings_paginator = access_analyzer.get_paginator("list_findings")
            findings_pages = list_findings_paginator.paginate(
                analyzerArn=analyzer_arn,
                filter={"status": {"eq": ["ACTIVE"]}}
            )

            aa_findings_count = 0

            for page in findings_pages:
                for finding_id in page.get("findings", []):
                    # Get detailed finding information
                    finding_detail = access_analyzer.get_finding(
                        analyzerArn=analyzer_arn,
                        id=finding_id["id"]
                    )

                    resource_type = finding_detail.get("resourceType", "Unknown")
                    resource = finding_detail.get("resource", "Unknown")

                    # Determine severity based on resource type and access
                    severity = (
                        "High"
                        if resource_type in ["AWS::S3::Bucket", "AWS::KMS::Key"]
                        else "Medium"
                    )

                    # Check if the resource is accessible from the internet
                    is_public = False
                    if "isPublic" in finding_detail and finding_detail["isPublic"]:
                        is_public = True
                        severity = "Critical"

                    findings.append({
                        "id": f"AA-{finding_id['id']}",
                        "category": "Access Analyzer",
                        "severity": severity,
                        "resource_type": resource_type,
                        "resource_id": resource,
                        "description": (
                            f"{resource_type} {resource} "
                            f"{'is publicly accessible' if is_public else 'has external access'} "
                            "that may not be intended"
                        ),
                        "recommendation": (
                            f"Review the permissions for this {resource_type} "
                            "and restrict access if unintended"
                        ),
                        "compliance": "AWS Well-Architected, CIS AWS Foundations",
                        "detection_date": datetime.datetime.now().isoformat(),
                    })

                    aa_findings_count += 1

            print(
                f"Found {aa_findings_count} Access Analyzer findings for analyzer "
                f"{analyzer_name}"
            )

            # If there were no findings, add a positive finding
            if aa_findings_count == 0:
                findings.append({
                    "id": f"AA-POSITIVE-{analyzer_name}",
                    "category": "Access Analyzer",
                    "severity": "Informational",
                    "resource_type": "IAM Access Analyzer",
                    "resource_id": analyzer_name,
                    "description": (
                        "No external access findings detected by IAM Access Analyzer"
                    ),
                    "recommendation": "Continue monitoring with IAM Access Analyzer",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat(),
                })

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting Access Analyzer findings: {error_msg}")
        findings.append({
            "id": "AA-ERROR",
            "category": "Access Analyzer",
            "severity": "Medium",
            "resource_type": "Access Analyzer Service",
            "resource_id": "error",
            "description": f"Error collecting Access Analyzer findings: {error_msg}",
            "recommendation": (
                "Check Lambda execution role permissions for Access Analyzer "
                "ReadOnly access"
            ),
            "compliance": "N/A",
            "detection_date": datetime.datetime.now().isoformat(),
        })

    print(f"Collected {len(findings)} Access Analyzer findings")
    return findings


def collect_cloudtrail_findings(cloudtrail, s3):
    """
    Collect CloudTrail-related security findings.
    Checks if CloudTrail is enabled and properly configured.
    """
    findings = []
    print("Collecting AWS CloudTrail findings...")

    try:
        # Get list of trails
        trails = cloudtrail.describe_trails().get("trailList", [])

        if not trails:
            findings.append({
                "id": "CT-NOT-ENABLED",
                "category": "CloudTrail",
                "severity": "High",
                "resource_type": "AWS CloudTrail",
                "resource_id": "none",
                "description": "CloudTrail is not enabled in this account",
                "recommendation": (
                    "Enable CloudTrail to track API activity across your AWS account"
                ),
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat()
            })
            return findings

        # Check each trail's configuration
        for trail in trails:
            trail_name = trail.get("Name", "")
            trail_arn = trail.get("TrailARN", "")
            s3_bucket = trail.get("S3BucketName", "")

            # Check if logging is enabled
            status = cloudtrail.get_trail_status(Name=trail_name)
            if not status.get("IsLogging", False):
                findings.append({
                    "id": f"CT-LOGGING-{trail_name[:8]}",
                    "category": "CloudTrail",
                    "severity": "High",
                    "resource_type": "AWS CloudTrail",
                    "resource_id": trail_arn,
                    "description": f"CloudTrail {trail_name} is not actively logging",
                    "recommendation": "Enable logging for the CloudTrail trail",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat()
                })

            # Check multi-region logging
            if not trail.get("IsMultiRegionTrail", False):
                findings.append({
                    "id": f"CT-REGION-{trail_name[:8]}",
                    "category": "CloudTrail",
                    "severity": "Medium",
                    "resource_type": "AWS CloudTrail",
                    "resource_id": trail_arn,
                    "description": (
                        f"CloudTrail {trail_name} is not configured for multi-region"
                    ),
                    "recommendation": "Enable multi-region logging for complete coverage",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat()
                })

            # Check management events
            selectors = cloudtrail.get_event_selectors(
                TrailName=trail_name
            ).get("EventSelectors", [])

            management_events_enabled = False
            for selector in selectors:
                if (
                    selector.get("ReadWriteType") == "All"
                    and selector.get("IncludeManagementEvents", False)
                ):
                    management_events_enabled = True
                    break

            if not management_events_enabled:
                findings.append({
                    "id": f"CT-MGMT-{trail_name[:8]}",
                    "category": "CloudTrail",
                    "severity": "Medium",
                    "resource_type": "AWS CloudTrail",
                    "resource_id": trail_arn,
                    "description": (
                        f"CloudTrail {trail_name} is not logging all management events"
                    ),
                    "recommendation": "Enable logging of all management events",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat()
                })

            # Check log file validation
            if not trail.get("LogFileValidationEnabled", False):
                findings.append({
                    "id": f"CT-VALID-{trail_name[:8]}",
                    "category": "CloudTrail",
                    "severity": "Low",
                    "resource_type": "AWS CloudTrail",
                    "resource_id": trail_arn,
                    "description": (
                        f"CloudTrail {trail_name} does not have log validation enabled"
                    ),
                    "recommendation": "Enable log file validation for integrity",
                    "compliance": "AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat()
                })

            # Check S3 bucket encryption
            try:
                s3.get_bucket_encryption(Bucket=s3_bucket)
            except Exception as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    findings.append({
                        "id": f"CT-ENC-{trail_name[:8]}",
                        "category": "CloudTrail",
                        "severity": "Medium",
                        "resource_type": "AWS CloudTrail",
                        "resource_id": trail_arn,
                        "description": (
                            f"S3 bucket {s3_bucket} for CloudTrail {trail_name} "
                            "is not encrypted"
                        ),
                        "recommendation": "Enable encryption for CloudTrail S3 bucket",
                        "compliance": "AWS Well-Architected",
                        "detection_date": datetime.datetime.now().isoformat()
                    })

        # If no findings detected, add a positive note
        if not findings:
            findings.append({
                "id": "CT-POSITIVE-001",
                "category": "CloudTrail",
                "severity": "Informational",
                "resource_type": "AWS CloudTrail",
                "resource_id": "account",
                "description": "CloudTrail is properly configured",
                "recommendation": "Continue monitoring CloudTrail configuration",
                "compliance": "AWS Well-Architected",
                "detection_date": datetime.datetime.now().isoformat()
            })

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting CloudTrail findings: {error_msg}")
        findings.append({
            "id": "CT-ERROR",
            "category": "CloudTrail",
            "severity": "Medium",
            "resource_type": "AWS CloudTrail",
            "resource_id": "error",
            "description": f"Error collecting findings: {error_msg}",
            "recommendation": "Check Lambda role permissions for CloudTrail",
            "compliance": "N/A",
            "detection_date": datetime.datetime.now().isoformat()
        })

    print(f"Collected {len(findings)} CloudTrail findings")
    return findings


def generate_ai_narrative(bedrock, findings):
    """
    Generate a narrative summary of findings using Amazon Bedrock.
    Uses AI to create a comprehensive analysis of security findings.
    """
    print("Generating AI narrative summary using Amazon Bedrock...")

    try:
        # Import from bedrock_integration.py
        from bedrock_integration import get_ai_analysis

        # If the import succeeded, use the real function
        return get_ai_analysis(bedrock, findings)
    except Exception as e:
        error_msg = str(e)
        print(f"Error using Bedrock integration: {error_msg}")
        print("Falling back to local narrative generation")

        # Fall back to a locally generated narrative if Bedrock fails
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Count findings by severity
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0
        }

        # Count findings by category
        category_counts = {}

        # Track key issues
        key_issues = []
        positives = []

        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "Medium")
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Count by category
            category = finding.get("category", "Other")
            if category not in category_counts:
                category_counts[category] = 0
            category_counts[category] += 1

            # Track critical and high findings as key issues
            if severity in ["Critical", "High"]:
                key_issues.append(
                    f"- {finding.get('description')} "
                    f"({finding.get('resource_type')}: {finding.get('resource_id')})"
                )

            # Track positive findings
            if (
                severity == "Informational"
                and "no " in finding.get("description", "").lower()
                or "positive" in finding.get("id", "").lower()
            ):
                positives.append(f"- {finding.get('description')}")

        # Sort categories by count
        sorted_categories = sorted(
            category_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Build the narrative
        narrative = (
            f"\nAWS Access Review Report - {timestamp}\n\n"
            "EXECUTIVE SUMMARY\n"
            "This automated security review has analyzed your AWS environment across "
            f"multiple security dimensions and identified {len(findings)} findings.\n\n"
            "FINDINGS SUMMARY\n"
            f"Total findings: {len(findings)}\n"
            f"Critical: {severity_counts['Critical']} - Requires immediate attention\n"
            f"High: {severity_counts['High']} - Should be addressed soon\n"
            f"Medium: {severity_counts['Medium']} - Should be planned for remediation\n"
            f"Low: {severity_counts['Low']} - Consider addressing when convenient\n"
            f"Informational: {severity_counts['Informational']} - No action needed\n\n"
            "FINDINGS BY CATEGORY\n"
        )

        for category, count in sorted_categories:
            narrative += f"{category}: {count} findings\n"

        if key_issues:
            narrative += (
                "\nKEY ISSUES REQUIRING ATTENTION\n"
                "The following critical or high severity issues were identified:\n"
                f"{chr(10).join(key_issues[:5])}\n"
            )
            if len(key_issues) > 5:
                narrative += (
                    f"...and {len(key_issues) - 5} more critical or high severity "
                    "issues.\n"
                )

        if positives:
            narrative += (
                "\nPOSITIVE SECURITY FINDINGS\n"
                "The following security best practices were detected:\n"
                f"{chr(10).join(positives[:3])}\n"
            )
            if len(positives) > 3:
                narrative += f"...and {len(positives) - 3} more positive findings.\n"

        narrative += (
            "\nRECOMMENDATIONS\n"
            "1. Address all Critical and High findings as soon as possible\n"
            "2. Create a remediation plan for Medium findings\n"
            "3. Schedule regular security reviews using this tool\n"
            "4. For detailed findings, please see the attached CSV report\n"
        )

        return narrative


def send_email_with_attachment(ses_client, recipient_email, narrative, csv_content, filename):
    """
    Send an email with a narrative and CSV attachment.
    """
    print(f"Preparing to send email to {recipient_email} with report attachment")

    # Create a multipart/mixed parent container
    msg = email.mime.multipart.MIMEMultipart("mixed")

    # Add subject, from, to headers
    msg["Subject"] = "AWS Access Review Report"
    msg["From"] = recipient_email  # Using recipient as sender (must be verified in SES)
    msg["To"] = recipient_email

    # Create a multipart/alternative child container for text and HTML versions
    msg_body = email.mime.multipart.MIMEMultipart("alternative")

    # Format the narrative for HTML (replace newlines with <br> tags)
    formatted_narrative = narrative.replace("\n", "<br>")

    # Plain text version of the message
    text_content = (
        "AWS Access Review Report\n\n"
        f"{narrative}\n\n"
        "Please see the attached CSV file for detailed findings."
    )
    text_part = email.mime.text.MIMEText(text_content, "plain")

    # HTML version of the message
    html_content = (
        "<html>\n"
        "<head></head>\n"
        "<body>\n"
        "<h1>AWS Access Review Report</h1>\n"
        f"<p>{formatted_narrative}</p>\n"
        "<p>Please see the attached CSV file for detailed findings.</p>\n"
        "</body>\n"
        "</html>"
    )
    html_part = email.mime.text.MIMEText(html_content, "html")

    # Add the text and HTML parts to the child container
    msg_body.attach(text_part)
    msg_body.attach(html_part)

    # Attach the multipart/alternative child container to the multipart/mixed parent
    msg.attach(msg_body)

    # Create the attachment
    attachment = email.mime.application.MIMEApplication(csv_content)
    attachment.add_header("Content-Disposition", "attachment", filename=filename)

    # Add the attachment to the message
    msg.attach(attachment)

    try:
        # Convert the message to a string and send it
        print("Attempting to send email via SES...")
        response = ses_client.send_raw_email(
            Source=recipient_email,
            Destinations=[recipient_email],
            RawMessage={"Data": msg.as_string()},
        )
        print(f"Email sent successfully! Message ID: {response['MessageId']}")
        return True
    except Exception as e:
        error_msg = str(e)
        print(f"Error sending email: {error_msg}")
        # Print SES verification status for debugging
        try:
            verification = ses_client.get_identity_verification_attributes(
                Identities=[recipient_email]
            )
            print(f"SES verification status: {verification}")
        except Exception as ve:
            error_msg = str(ve)
            print(f"Could not check verification status: {error_msg}")
        return False


def verify_email_for_ses(ses_client, email_address):
    """
    Verify an email address with SES if it's not already verified.
    """
    try:
        # Check if the email is already verified
        response = ses_client.get_identity_verification_attributes(
            Identities=[email_address]
        )

        # If the email is not in the response or not verified, send verification
        if (
            email_address not in response["VerificationAttributes"]
            or response["VerificationAttributes"][email_address]["VerificationStatus"]
            != "Success"
        ):
            print(f"Email {email_address} not verified. Sending verification email...")
            ses_client.verify_email_identity(EmailAddress=email_address)
            print(
                f"Verification email sent to {email_address}. "
                "Please check your inbox and verify."
            )
        else:
            print(f"Email {email_address} is already verified in SES.")
    except Exception as e:
        error_msg = str(e)
        print(f"Error checking/verifying email: {error_msg}")
        raise
