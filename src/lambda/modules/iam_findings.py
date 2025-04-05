"""
Module for collecting AWS IAM-related security findings.
"""

import datetime


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
                    findings.append(
                        {
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
                        }
                    )

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
                    findings.append(
                        {
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
                        }
                    )

            # Check for wide permissions (admin access)
            attached_policies = iam.list_attached_user_policies(UserName=username)[
                "AttachedPolicies"
            ]
            for policy in attached_policies:
                if (
                    "admin" in policy["PolicyName"].lower()
                    or "administrator" in policy["PolicyName"].lower()
                ):
                    findings.append(
                        {
                            "id": f"IAM-003-{username}",
                            "category": "IAM",
                            "severity": "Medium",
                            "resource_type": "IAM User",
                            "resource_id": username,
                            "description": (
                                f"User {username} has potentially wide privileges via "
                                f'policy {policy["PolicyName"]}'
                            ),
                            "recommendation": "Apply least privilege principle to IAM users",
                            "compliance": "CIS 1.16, AWS Well-Architected",
                            "detection_date": datetime.datetime.now().isoformat(),
                        }
                    )

        # Check for unused roles
        response = iam.list_roles()
        roles = response["Roles"]
        while response.get("IsTruncated", False):
            response = iam.list_roles(Marker=response["Marker"])
            roles.extend(response["Roles"])

        for role in roles:
            role_name = role["RoleName"]
            if "service-role/" not in role["Path"] and not role_name.startswith(
                "AWSServiceRole"
            ):
                last_used_response = (
                    iam.get_role(RoleName=role_name)
                    .get("Role", {})
                    .get("RoleLastUsed", {})
                )
                if "LastUsedDate" not in last_used_response:
                    findings.append(
                        {
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
                        }
                    )

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
                findings.append(
                    {
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
                    }
                )
        except iam.exceptions.NoSuchEntityException:
            findings.append(
                {
                    "id": "IAM-006",
                    "category": "IAM",
                    "severity": "High",
                    "resource_type": "IAM Password Policy",
                    "resource_id": "account-password-policy",
                    "description": "No IAM password policy is set for the account",
                    "recommendation": "Configure a strong password policy",
                    "compliance": "CIS 1.5-1.11, AWS Well-Architected",
                    "detection_date": datetime.datetime.now().isoformat(),
                }
            )

    except Exception as e:
        error_msg = str(e)
        print(f"Error collecting IAM findings: {error_msg}")
        findings.append(
            {
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
            }
        )

    print(f"Collected {len(findings)} IAM findings")
    return findings
