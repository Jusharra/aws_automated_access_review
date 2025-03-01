import os
import sys
import pytest
import unittest
from unittest.mock import patch, MagicMock

# Add the lambda directory to the path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/lambda"))
)
import index  # noqa: E402


@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for boto3."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def s3(aws_credentials):
    """Mock S3 client without using moto."""
    s3_client = MagicMock()

    # Mock the create_bucket method
    s3_client.create_bucket.return_value = {"Location": "/test-report-bucket"}

    # Mock the list_objects_v2 method
    s3_client.list_objects_v2.return_value = {"Contents": []}

    # Mock the delete_object method
    s3_client.delete_object.return_value = {}

    # Mock the delete_bucket method
    s3_client.delete_bucket.return_value = {}

    return s3_client


@pytest.fixture
def ses(aws_credentials):
    """Mock SES client without using moto."""
    ses_client = MagicMock()
    return ses_client


@pytest.fixture
def lambda_environment():
    """Set up Lambda environment variables."""
    os.environ["REPORT_BUCKET"] = "test-report-bucket"
    os.environ["RECIPIENT_EMAIL"] = "test@example.com"


def test_handler_success(s3, ses, lambda_environment):
    """Test the Lambda handler with successful execution."""
    print("\n=== STARTING test_handler_success TEST ===")

    # Create a very simple mock setup
    findings = [
        {
            "id": "iam-1",
            "category": "IAM",
            "severity": "Medium",
            "resource_type": "IAM Role",
            "resource_id": "test-role",
            "description": "Test IAM finding",
            "recommendation": "Test recommendation",
            "compliance": "CIS 1.2",
            "detection_date": "2023-01-01T00:00:00",
        }
    ]

    # Create the S3 bucket
    print("Creating test bucket")
    bucket_name = "test-report-bucket"
    s3.create_bucket(Bucket=bucket_name)
    print("Bucket created successfully")

    # Use a simpler patching approach with fewer dependencies
    patches = []

    try:
        print("Setting up patches...")

        # Create minimal patches
        boto3_patch = patch("boto3.client", autospec=True)
        mock_boto3 = boto3_patch.start()
        patches.append(boto3_patch)
        print("boto3.client patched")

        # Setup mock clients
        mock_boto3.return_value = MagicMock()
        print("Mock client setup complete")

        # Simple patch for all collection functions to return a basic finding
        for func_name in [
            "collect_iam_findings",
            "collect_scp_findings",
            "collect_securityhub_findings",
            "collect_access_analyzer_findings",
            "collect_cloudtrail_findings",
        ]:
            p = patch(f"index.{func_name}", return_value=findings)
            p.start()
            patches.append(p)
            print(f"Patched {func_name}")

        # Mock the narrative and email functions
        narrative_patch = patch(
            "index.generate_ai_narrative", return_value="Test narrative"
        )
        narrative_patch.start()
        patches.append(narrative_patch)
        print("Patched generate_ai_narrative")

        email_patch = patch("index.send_email_with_attachment")
        email_patch.start()
        patches.append(email_patch)
        print("Patched send_email_with_attachment")

        # Make verify_email a no-op
        verify_patch = patch("index.verify_email_for_ses")
        verify_patch.start()
        patches.append(verify_patch)
        print("Patched verify_email_for_ses")

        print("All patches applied, calling handler...")

        # Call the handler with simplified mocks
        response = index.handler({}, {})
        print(f"Handler response: {response}")

        # Simple assertions
        assert (
            response["statusCode"] == 200
        ), f"Expected status 200, got {response['statusCode']}"
        print("Test completed successfully!")

    except Exception as e:
        print(f"ERROR in test: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        raise
    finally:
        print("Cleaning up patches...")
        # Stop all patches
        for i, p in enumerate(patches):
            try:
                p.stop()
                print(f"Stopped patch {i + 1}/{len(patches)}")
            except Exception as e:
                print(f"Error stopping patch {i + 1}/{len(patches)}: {e}")

        print("Cleaning up S3 bucket...")
        try:
            # Delete any objects in the bucket first
            try:
                objects = s3.list_objects_v2(Bucket=bucket_name)
                if "Contents" in objects:
                    for obj in objects["Contents"]:
                        print(f"Deleting object: {obj['Key']}")
                        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
                    print("All objects deleted from bucket")
            except Exception as e:
                print(f"Error listing/deleting bucket objects: {e}")

            # Now delete the bucket
            s3.delete_bucket(Bucket=bucket_name)
            print("S3 bucket deleted")
        except Exception as e:
            print(f"Error deleting S3 bucket: {e}")

        print("=== FINISHED test_handler_success TEST ===")


def test_collect_iam_findings():
    """Test the IAM findings collection function."""
    print("\n=== STARTING test_collect_iam_findings TEST ===")

    # Create a properly configured mock
    mock_iam = MagicMock()

    # Configure all the necessary mock responses
    print("Setting up IAM mock responses...")

    # Mock roles
    mock_iam.list_roles.return_value = {
        "Roles": [
            {
                "RoleName": "test-role",
                "Path": "/",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
            }
        ]
    }

    # Mock users
    mock_iam.list_users.return_value = {
        "Users": [
            {
                "UserName": "test-user",
                "Path": "/",
                "Arn": "arn:aws:iam::123456789012:user/test-user",
            }
        ]
    }

    # Mock role policies
    mock_iam.list_attached_role_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "test-policy",
                "PolicyArn": "arn:aws:iam::123456789012:policy/test-policy",
            }
        ]
    }

    # Mock user policies
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "test-policy",
                "PolicyArn": "arn:aws:iam::123456789012:policy/test-policy",
            }
        ]
    }

    # Mock policy details
    mock_iam.get_policy.return_value = {
        "Policy": {
            "PolicyName": "test-policy",
            "DefaultVersionId": "v1",
            "Arn": "arn:aws:iam::123456789012:policy/test-policy",
        }
    }

    # Mock policy version
    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
            }
        }
    }

    print("IAM mock setup complete")

    try:
        # Call the function
        print("Calling collect_iam_findings...")
        findings = index.collect_iam_findings(mock_iam)
        print(f"Got {len(findings)} findings")

        # Verify the results
        assert len(findings) > 0, "Expected at least one finding"
        assert (
            findings[0]["category"] == "IAM"
        ), f"Expected category 'IAM', got '{findings[0].get('category')}'"
        assert "severity" in findings[0], "Missing 'severity' in finding"
        assert "description" in findings[0], "Missing 'description' in finding"

        print("Assertions passed")

        # Verify method calls
        mock_iam.list_roles.assert_called_once()
        mock_iam.list_users.assert_called_once()
        print("Method call assertions passed")

    except Exception as e:
        print(f"ERROR in test: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        raise
    finally:
        print("=== FINISHED test_collect_iam_findings TEST ===")


def test_collect_scp_findings():
    """Test the SCP findings collection function."""
    print("\n=== STARTING test_collect_scp_findings TEST ===")

    # Create a properly configured mock
    mock_org = MagicMock()

    # Configure all the necessary mock responses
    print("Setting up Organizations mock responses...")

    # Mock list_policies
    mock_org.list_policies.return_value = {
        "Policies": [
            {
                "Id": "p-12345678",
                "Name": "test-scp",
                "Description": "Test SCP",
                "Type": "SERVICE_CONTROL_POLICY",
            }
        ]
    }

    # Mock describe_policy
    mock_org.describe_policy.return_value = {
        "Policy": {
            "Id": "p-12345678",
            "Name": "test-scp",
            "Description": "Test SCP",
            "Content": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
            ),
            "Type": "SERVICE_CONTROL_POLICY",
        }
    }

    print("Organizations mock setup complete")

    try:
        # Call the function
        print("Calling collect_scp_findings...")
        findings = index.collect_scp_findings(mock_org)
        print(f"Got {len(findings)} findings")

        # Verify the results
        assert len(findings) > 0, "Expected at least one finding"
        assert (
            findings[0]["category"] == "SCP"
        ), f"Expected category 'SCP', got '{findings[0].get('category')}'"
        assert "severity" in findings[0], "Missing 'severity' in finding"
        assert "description" in findings[0], "Missing 'description' in finding"

        print("Assertions passed")

    except Exception as e:
        print(f"ERROR in test: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        raise
    finally:
        print("=== FINISHED test_collect_scp_findings TEST ===")


def test_collect_cloudtrail_findings():
    """Test the CloudTrail findings collection function."""
    print("\n=== STARTING test_collect_cloudtrail_findings TEST ===")

    # Create a properly configured mock
    mock_cloudtrail = MagicMock()
    mock_s3 = MagicMock()  # Add mock S3 client

    # Track all mocks that need to be explicitly reset
    mocks_to_cleanup = [mock_cloudtrail, mock_s3]

    # Configure all the necessary mock responses
    print("Setting up CloudTrail mock responses...")

    # Mock describe_trails
    mock_cloudtrail.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "test-trail",
                "S3BucketName": "test-bucket",
                "IsMultiRegionTrail": False,
                "HomeRegion": "us-east-1",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
            }
        ]
    }

    # Mock get_trail_status
    mock_cloudtrail.get_trail_status.return_value = {
        "IsLogging": True,
        "LatestDeliveryError": "",
        "LatestNotificationError": "",
        "LatestDeliveryTime": "2023-01-01T00:00:00Z",
        "LatestNotificationTime": "2023-01-01T00:00:00Z",
        "StartLoggingTime": "2023-01-01T00:00:00Z",
        "StopLoggingTime": "2023-01-01T00:00:00Z",
        "LatestCloudWatchLogsDeliveryError": "",
        "LatestCloudWatchLogsDeliveryTime": "2023-01-01T00:00:00Z",
    }

    # Mock get_event_selectors
    mock_cloudtrail.get_event_selectors.return_value = {
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [],
            }
        ],
    }

    # Configure S3 mock responses
    print("Setting up S3 mock responses...")
    mock_s3.list_objects_v2.return_value = {"Contents": []}
    mock_s3.get_bucket_encryption.side_effect = Exception(
        "ServerSideEncryptionConfigurationNotFoundError"
    )

    print("CloudTrail mock setup complete")

    try:
        # Call the function
        print("Calling collect_cloudtrail_findings...")
        findings = index.collect_cloudtrail_findings(mock_cloudtrail, mock_s3)
        print(f"Got {len(findings)} findings")

        # Verify the results
        assert len(findings) > 0, "Expected at least one finding"
        assert (
            findings[0]["category"] == "CloudTrail"
        ), f"Expected category 'CloudTrail', got '{findings[0].get('category')}'"
        assert "severity" in findings[0], "Missing 'severity' in finding"
        assert "description" in findings[0], "Missing 'description' in finding"

        # Verify method calls
        mock_cloudtrail.describe_trails.assert_called_once()
        mock_cloudtrail.get_trail_status.assert_called_once()
        mock_cloudtrail.get_event_selectors.assert_called_once()

        print("Assertions passed")

    except Exception as e:
        print(f"ERROR in test: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        raise
    finally:
        # Explicit cleanup of mocks
        print("Cleaning up mocks...")
        for i, mock in enumerate(mocks_to_cleanup):
            try:
                mock.reset_mock()
                print(f"Reset mock {i + 1}/{len(mocks_to_cleanup)}")
            except Exception as e:
                print(f"Error resetting mock {i + 1}: {e}")

        print("=== FINISHED test_collect_cloudtrail_findings TEST ===")


def test_handler_exception_handling(lambda_environment):
    """Test the Lambda handler's exception handling."""
    print("\n=== STARTING test_handler_exception_handling TEST ===")

    # Mock boto3.client to raise an exception
    mock_patch = None
    try:
        print("Setting up exception mock...")
        mock_patch = patch("boto3.client", side_effect=Exception("Test exception"))
        mock_patch.start()
        print("Mock setup complete")

        # Call the handler
        print("Calling handler with exception mock...")
        response = index.handler({}, {})
        print(f"Handler response: {response}")

        # Verify the response
        assert (
            response["statusCode"] == 500
        ), f"Expected status 500, got {response['statusCode']}"
        assert "Error" in response["body"], "Expected 'Error' in response body"
        assert (
            "Test exception" in response["body"]
        ), "Expected exception message in response body"
        print("Assertions passed")

    except Exception as e:
        print(f"ERROR in test: {type(e).__name__}: {e}")
        import traceback

        traceback.print_exc()
        # If the handler doesn't catch the exception, we'll catch it here
        # and verify it's the expected exception
        assert str(e) == "Test exception", f"Expected 'Test exception', got '{str(e)}'"
        print("Exception assertion passed")

    finally:
        # Ensure the mock is stopped to avoid affecting other tests
        print("Cleaning up mock...")
        if mock_patch:
            try:
                mock_patch.stop()
                print("Mock stopped successfully")
            except Exception as e:
                print(f"Error stopping mock: {e}")

        print("=== FINISHED test_handler_exception_handling TEST ===")


class TestHandler(unittest.TestCase):
    """Test cases for the Lambda handler."""

    def setUp(self):
        self.patches = []

    def tearDown(self):
        # Clean up all patches
        for p in self.patches:
            p.stop()
        self.patches.clear()

    def create_patch(self, target):
        patcher = patch(target)
        self.patches.append(patcher)
        return patcher.start()

    @patch("index.collect_iam_findings")
    @patch("index.collect_securityhub_findings")
    @patch("index.collect_access_analyzer_findings")
    @patch("index.collect_cloudtrail_findings")
    @patch("index.collect_scp_findings")
    @patch("index.generate_ai_narrative")
    @patch("boto3.client")
    def test_lambda_handler(
        self,
        mock_boto3_client,
        mock_generate_ai_narrative,
        mock_collect_scp_findings,
        mock_collect_cloudtrail_findings,
        mock_collect_access_analyzer_findings,
        mock_collect_securityhub_findings,
        mock_collect_iam_findings,
    ):
        """Test the Lambda handler function."""
        # Mock AWS clients
        mock_s3 = MagicMock()
        mock_ses = MagicMock()

        # Configure boto3.client to return our mocks
        def mock_client(service_name, *args, **kwargs):
            if service_name == "s3":
                return mock_s3
            elif service_name == "ses":
                return mock_ses
            else:
                # Return a new MagicMock for any other service
                return MagicMock()

        mock_boto3_client.side_effect = mock_client

        # Mock the findings
        mock_collect_iam_findings.return_value = [{"id": "iam-1", "category": "IAM"}]
        mock_collect_securityhub_findings.return_value = [
            {"id": "sh-1", "category": "Security Hub"}
        ]
        mock_collect_access_analyzer_findings.return_value = [
            {"id": "aa-1", "category": "Access Analyzer"}
        ]
        mock_collect_cloudtrail_findings.return_value = [
            {"id": "ct-1", "category": "CloudTrail"}
        ]
        mock_collect_scp_findings.return_value = [{"id": "scp-1", "category": "SCP"}]

        # Mock the narrative
        mock_generate_ai_narrative.return_value = "Test narrative"

        # Set up environment variables
        with patch.dict(
            os.environ,
            {"REPORT_BUCKET": "test-bucket", "RECIPIENT_EMAIL": "test@example.com"},
        ):
            try:
                # Call the handler
                event = {}
                context = MagicMock()
                response = index.handler(event, context)

                # Assertions
                self.assertEqual(response["statusCode"], 200)
                self.assertIn(
                    "AWS Access Review completed successfully", response["body"]
                )

                # Verify all the functions were called
                mock_collect_iam_findings.assert_called_once()
                mock_collect_securityhub_findings.assert_called_once()
                mock_collect_access_analyzer_findings.assert_called_once()
                mock_collect_cloudtrail_findings.assert_called_once()
                mock_collect_scp_findings.assert_called_once()
                mock_generate_ai_narrative.assert_called_once()

                # Verify S3 and SES operations
                mock_s3.put_object.assert_called_once()
                mock_ses.send_raw_email.assert_called_once()
            finally:
                # Clean up any resources that might have been created
                print("Cleaning up resources...")


class TestIAMFindings(unittest.TestCase):
    """Test cases for IAM findings collection."""

    @patch("boto3.client")
    def test_collect_iam_findings(self, mock_boto3_client):
        """Test the collect_iam_findings function."""
        # Mock the IAM client
        mock_iam = MagicMock()
        mock_boto3_client.return_value = mock_iam

        # Mock the IAM responses
        mock_iam.list_roles.return_value = {"Roles": [{"RoleName": "test-role"}]}
        mock_iam.list_users.return_value = {"Users": [{"UserName": "test-user"}]}
        mock_iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "test-policy",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/test-policy",
                }
            ]
        }
        mock_iam.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "test-policy",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/test-policy",
                }
            ]
        }
        mock_iam.get_policy.return_value = {
            "Policy": {
                "DefaultVersionId": "v1",
                "Arn": "arn:aws:iam::123456789012:policy/test-policy",
            }
        }
        mock_iam.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
                }
            }
        }

        # Call the function
        findings = index.collect_iam_findings(mock_iam)

        # Assertions
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        mock_iam.list_roles.assert_called_once()
        mock_iam.list_users.assert_called_once()


class TestSecurityHubFindings(unittest.TestCase):
    """Test cases for Security Hub findings collection."""

    @patch("boto3.client")
    def test_collect_securityhub_findings(self, mock_boto3_client):
        """Test the collect_securityhub_findings function."""
        print(
            "\n=== STARTING TestSecurityHubFindings.test_collect_securityhub_findings TEST ==="
        )

        try:
            # Mock the Security Hub client
            mock_securityhub = MagicMock()
            mock_boto3_client.return_value = mock_securityhub

            # Mock get_enabled_standards
            mock_securityhub.get_enabled_standards.return_value = {
                "StandardsSubscriptions": [
                    {
                        "StandardsArn": (
                            "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
                        ),
                        "StandardsSubscriptionArn": (
                            "arn:aws:securityhub:us-east-1:123456789012:"
                            "subscription/cis-aws-foundations-benchmark/v/1.2.0"
                        ),
                        "StandardsInput": {"string": "string"},
                        "StandardsStatus": "READY",
                    }
                ]
            }

            # Mock the paginator
            mock_paginator = MagicMock()
            mock_securityhub.get_paginator.return_value = mock_paginator

            # Correctly mock the paginate method with filters
            mock_paginator.paginate.return_value = [
                {
                    "Findings": [
                        {
                            "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/sh-1",
                            "Title": "Test finding",
                            "Description": "Test description",
                            "Severity": {"Label": "HIGH"},
                            "Resources": [{"Type": "AwsIamRole", "Id": "test-role"}],
                            "Compliance": {"Status": "FAILED"},
                            "FirstObservedAt": "2023-01-01T00:00:00Z",
                            "Remediation": {
                                "Recommendation": {"Text": "Fix this issue"}
                            },
                        }
                    ]
                }
            ]

            print("Calling collect_securityhub_findings...")
            # Call the function
            findings = index.collect_securityhub_findings(mock_securityhub)

            # Assertions
            self.assertIsInstance(findings, list)
            self.assertGreater(len(findings), 0)
            mock_securityhub.get_enabled_standards.assert_called_once()
            mock_securityhub.get_paginator.assert_called_once_with("get_findings")
            mock_paginator.paginate.assert_called_once()
            print("Assertions passed")

        except Exception as e:
            print(f"ERROR in test: {type(e).__name__}: {e}")
            import traceback

            traceback.print_exc()
            raise
        finally:
            print(
                "=== FINISHED TestSecurityHubFindings.test_collect_securityhub_findings TEST ==="
            )


class TestAccessAnalyzerFindings(unittest.TestCase):
    """Test cases for Access Analyzer findings collection."""

    @patch("boto3.client")
    def test_collect_access_analyzer_findings(self, mock_boto3_client):
        """Test the collect_access_analyzer_findings function."""
        # Mock the Access Analyzer client
        mock_analyzer = MagicMock()
        mock_boto3_client.return_value = mock_analyzer

        # Mock the Access Analyzer responses
        mock_analyzer.list_analyzers.return_value = {
            "analyzers": [
                {
                    "arn": "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/test-analyzer"
                }
            ]
        }
        mock_analyzer.list_findings.return_value = {
            "findings": [
                {
                    "id": "aa-1",
                    "resource": "arn:aws:s3:::test-bucket",
                    "resourceType": "AWS::S3::Bucket",
                    "status": "ACTIVE",
                    "createdAt": "2023-01-01T00:00:00Z",
                }
            ]
        }

        # Call the function
        findings = index.collect_access_analyzer_findings(mock_analyzer)

        # Assertions
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        mock_analyzer.list_analyzers.assert_called_once()
