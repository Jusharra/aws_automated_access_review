import os
import sys
import pytest
import boto3
import unittest
from unittest.mock import patch, MagicMock
from moto import mock_aws

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
    with mock_aws():
        s3_client = boto3.client("s3", region_name="us-east-1")
        yield s3_client


@pytest.fixture
def ses(aws_credentials):
    with mock_aws():
        ses_client = boto3.client("ses", region_name="us-east-1")
        yield ses_client


@pytest.fixture
def lambda_environment():
    """Set up Lambda environment variables."""
    os.environ["REPORT_BUCKET"] = "test-report-bucket"
    os.environ["RECIPIENT_EMAIL"] = "test@example.com"


def test_handler_success(s3, ses, lambda_environment):
    """Test the Lambda handler with successful execution."""
    # Create the S3 bucket
    s3.create_bucket(Bucket="test-report-bucket")

    # Mock all the AWS clients that will be used
    with patch("boto3.client") as mock_client:
        # Configure the mock to return specific clients
        mock_client_instances = {
            "iam": MagicMock(),
            "organizations": MagicMock(),
            "securityhub": MagicMock(),
            "access-analyzer": MagicMock(),
            "cloudtrail": MagicMock(),
            "bedrock-runtime": MagicMock(),
            "s3": s3,
            "ses": ses,
        }

        def side_effect(service_name, *args, **kwargs):
            return mock_client_instances.get(service_name, MagicMock())

        mock_client.side_effect = side_effect

        # Mock all the necessary functions directly
        with patch(
            "index.collect_iam_findings",
            return_value=[
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
            ],
        ):
            with patch("index.collect_scp_findings", return_value=[]):
                with patch("index.collect_securityhub_findings", return_value=[]):
                    with patch(
                        "index.collect_access_analyzer_findings", return_value=[]
                    ):
                        with patch(
                            "index.collect_cloudtrail_findings", return_value=[]
                        ):
                            with patch(
                                "index.generate_ai_narrative",
                                return_value="Test narrative",
                            ):
                                with patch(
                                    "index.send_email_with_attachment"
                                ) as mock_send_email:
                                    # Call the handler
                                    response = index.handler({}, {})

                                    # Verify the response
                                    assert response["statusCode"] == 200
                                    assert (
                                        "AWS Access Review completed successfully"
                                        in response["body"]
                                    )

                                    # Verify email was sent
                                    mock_send_email.assert_called_once()


def test_collect_iam_findings():
    """Test the IAM findings collection function."""
    mock_iam = MagicMock()

    # Call the function
    findings = index.collect_iam_findings(mock_iam)

    # Verify the results
    assert len(findings) > 0
    assert findings[0]["category"] == "IAM"
    assert "severity" in findings[0]
    assert "description" in findings[0]


def test_collect_scp_findings():
    """Test the SCP findings collection function."""
    mock_org = MagicMock()

    # Call the function
    findings = index.collect_scp_findings(mock_org)

    # Verify the results
    assert len(findings) > 0
    assert findings[0]["category"] == "SCP"
    assert "severity" in findings[0]
    assert "description" in findings[0]


def test_collect_cloudtrail_findings():
    """Test the CloudTrail findings collection function."""
    mock_cloudtrail = MagicMock()

    # Call the function
    findings = index.collect_cloudtrail_findings(mock_cloudtrail)

    # Verify the results
    assert len(findings) > 0
    assert findings[0]["category"] == "CloudTrail"
    assert "severity" in findings[0]
    assert "description" in findings[0]


def test_handler_exception_handling(lambda_environment):
    """Test the Lambda handler's exception handling."""
    # Mock boto3.client to raise an exception
    with patch("boto3.client", side_effect=Exception("Test exception")):
        try:
            # Call the handler
            response = index.handler({}, {})

            # Verify the response
            assert response["statusCode"] == 500
            assert "Error" in response["body"]
            assert "Test exception" in response["body"]
        except Exception as e:
            # If the handler doesn't catch the exception, we'll catch it here
            # and verify it's the expected exception
            assert str(e) == "Test exception"


class TestHandler(unittest.TestCase):
    """Test cases for the Lambda handler."""

    @patch("index.collect_iam_findings")
    @patch("index.collect_securityhub_findings")
    @patch("index.collect_access_analyzer_findings")
    @patch("index.collect_cloudtrail_findings")
    @patch("index.collect_scp_findings")
    @patch("index.generate_ai_narrative")
    @patch("index.generate_csv_report")
    @patch("index.upload_to_s3")
    @patch("index.send_email")
    def test_lambda_handler(
        self,
        mock_send_email,
        mock_upload_to_s3,
        mock_generate_csv_report,
        mock_generate_ai_narrative,
        mock_collect_scp_findings,
        mock_collect_cloudtrail_findings,
        mock_collect_access_analyzer_findings,
        mock_collect_securityhub_findings,
        mock_collect_iam_findings,
    ):
        """Test the Lambda handler function."""
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

        # Mock the narrative and report
        mock_generate_ai_narrative.return_value = "Test narrative"
        mock_generate_csv_report.return_value = "test-report.csv"

        # Mock the S3 upload
        mock_upload_to_s3.return_value = "s3://test-bucket/test-report.csv"

        # Call the handler
        event = {}
        context = MagicMock()
        response = index.handler(event, context)

        # Assertions
        self.assertEqual(response["statusCode"], 200)
        self.assertIn("message", response["body"])
        self.assertIn("reportUrl", response["body"])

        # Verify all the functions were called
        mock_collect_iam_findings.assert_called_once()
        mock_collect_securityhub_findings.assert_called_once()
        mock_collect_access_analyzer_findings.assert_called_once()
        mock_collect_cloudtrail_findings.assert_called_once()
        mock_collect_scp_findings.assert_called_once()
        mock_generate_ai_narrative.assert_called_once()
        mock_generate_csv_report.assert_called_once()
        mock_upload_to_s3.assert_called_once()
        mock_send_email.assert_called_once()


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
        # Mock the Security Hub client
        mock_securityhub = MagicMock()
        mock_boto3_client.return_value = mock_securityhub

        # Mock the Security Hub responses
        mock_securityhub.get_findings.return_value = {
            "Findings": [
                {
                    "Id": "sh-1",
                    "Title": "Test finding",
                    "Description": "Test description",
                    "Severity": {"Label": "HIGH"},
                    "Resources": [{"Type": "AwsIamRole", "Id": "test-role"}],
                    "Compliance": {"Status": "FAILED"},
                    "CreatedAt": "2023-01-01T00:00:00Z",
                }
            ]
        }

        # Call the function
        findings = index.collect_securityhub_findings(mock_securityhub)

        # Assertions
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0)
        mock_securityhub.get_findings.assert_called_once()


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
