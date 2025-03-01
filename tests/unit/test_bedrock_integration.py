import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Add the lambda directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), "../../src/lambda"))
import bedrock_integration  # noqa: E402


class TestBedrockIntegration(unittest.TestCase):
    """Test cases for the Bedrock integration module."""

    def test_prepare_prompt(self):
        """Test the prepare_prompt function."""
        # Sample findings data
        findings = [
            {
                "id": "finding1",
                "category": "IAM",
                "severity": "HIGH",
                "resource_type": "AWS::IAM::Policy",
                "description": "Overly permissive IAM policy",
            },
            {
                "id": "finding2",
                "category": "IAM",
                "severity": "MEDIUM",
                "resource_type": "AWS::IAM::Role",
                "description": "Role with unused permissions",
            },
            {
                "id": "finding3",
                "category": "Security Hub",
                "severity": "CRITICAL",
                "resource_type": "AWS::IAM::User",
                "description": "User with console access but no MFA",
            },
        ]

        # Call the function
        prompt = bedrock_integration.prepare_prompt(findings)

        # Assertions
        self.assertIsInstance(prompt, str)
        self.assertIn("AWS Access Review", prompt)
        self.assertIn("HIGH: 1", prompt)
        self.assertIn("MEDIUM: 1", prompt)
        self.assertIn("CRITICAL: 1", prompt)
        self.assertIn("IAM: 2", prompt)
        self.assertIn("Security Hub: 1", prompt)


class TestTitanModelIntegration(unittest.TestCase):
    """Test cases for the Titan model integration."""

    @patch("boto3.client")
    def test_invoke_titan_model(self, mock_boto3_client):
        """Test the invoke_titan_model function."""
        # Mock the Bedrock client
        mock_bedrock = MagicMock()
        mock_boto3_client.return_value = mock_bedrock

        # Mock the response from Bedrock
        mock_response = {
            "inputTokenCount": 100,
            "outputTokenCount": 50,
            "completion": "This is a test narrative.",
        }
        mock_bedrock.invoke_model.return_value = {
            "body": MagicMock(
                read=MagicMock(return_value=json.dumps(mock_response).encode())
            )
        }

        # Call the function
        prompt = "Generate a narrative for AWS Access Review"
        response = bedrock_integration.invoke_titan_model(mock_bedrock, prompt)

        # Assertions
        self.assertEqual(response, mock_response)
        mock_bedrock.invoke_model.assert_called_once()
        args, kwargs = mock_bedrock.invoke_model.call_args
        body = json.loads(kwargs["body"])
        self.assertEqual(body["inputText"], prompt)


class TestNarrativeExtraction(unittest.TestCase):
    """Test cases for narrative extraction."""

    def test_extract_narrative(self):
        """Test the extract_narrative function."""
        # Sample response from Titan model
        response = {
            "inputTokenCount": 100,
            "outputTokenCount": 50,
            "completion": "This is a test narrative.",
        }

        # Call the function
        narrative = bedrock_integration.extract_narrative(response)

        # Assertions
        self.assertEqual(narrative, "This is a test narrative.")


class TestFallbackNarrative(unittest.TestCase):
    """Test cases for fallback narrative generation."""

    def test_generate_fallback_narrative(self):
        """Test the generate_fallback_narrative function."""
        # Call the function
        narrative = bedrock_integration.generate_fallback_narrative()

        # Assertions
        self.assertIsInstance(narrative, str)
        self.assertIn("AWS Access Review", narrative)
        self.assertIn("Unable to generate AI-powered narrative", narrative)


class TestGenerateNarrative(unittest.TestCase):
    """Test cases for the generate_narrative function."""

    @patch("bedrock_integration.invoke_titan_model")
    @patch("bedrock_integration.extract_narrative")
    @patch("boto3.client")
    def test_generate_narrative_success(
        self, mock_boto3_client, mock_extract_narrative, mock_invoke_titan_model
    ):
        """Test the generate_narrative function with successful API call."""
        # Mock the Bedrock client
        mock_bedrock = MagicMock()
        mock_boto3_client.return_value = mock_bedrock

        # Mock the response from invoke_titan_model
        mock_response = {"completion": "This is a test narrative."}
        mock_invoke_titan_model.return_value = mock_response

        # Mock the extracted narrative
        mock_extract_narrative.return_value = "This is a test narrative."

        # Sample findings data
        findings = [
            {
                "id": "finding1",
                "category": "IAM",
                "severity": "HIGH",
                "resource_type": "AWS::IAM::Policy",
                "description": "Overly permissive IAM policy",
            }
        ]

        # Call the function
        narrative = bedrock_integration.generate_narrative(findings)

        # Assertions
        self.assertEqual(narrative, "This is a test narrative.")
        mock_boto3_client.assert_called_once_with("bedrock-runtime")
        mock_invoke_titan_model.assert_called_once()
        mock_extract_narrative.assert_called_once_with(mock_response)
