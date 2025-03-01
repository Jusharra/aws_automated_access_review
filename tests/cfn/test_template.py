import os
import re

# Import the template file
template_path = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "templates",
    "access-review.yaml",
)


def test_template_exists():
    """Test that the CloudFormation template file exists."""
    assert os.path.isfile(template_path), "Template file does not exist"


def test_template_is_valid_yaml():
    """Test that the CloudFormation template has valid structure."""
    with open(template_path, "r") as f:
        content = f.read()

    # Check for basic YAML structure without parsing
    assert "AWSTemplateFormatVersion:" in content, "Missing AWSTemplateFormatVersion"
    assert "Resources:" in content, "Missing Resources section"
    assert "Description:" in content, "Missing Description"


def test_template_has_required_resources():
    """Test that the CloudFormation template has the required resources."""
    with open(template_path, "r") as f:
        content = f.read()

    # Check for required resources using regex
    assert re.search(
        r"AccessReviewLambda:\s+Type:\s+AWS::Lambda::Function", content, re.MULTILINE
    ), "Lambda function resource is missing"
    assert re.search(
        r"ReportBucket:\s+Type:\s+AWS::S3::Bucket", content, re.MULTILINE
    ), "S3 bucket resource is missing"
    assert re.search(
        r"AccessReviewLambdaRole:\s+Type:\s+AWS::IAM::Role", content, re.MULTILINE
    ), "Lambda execution role is missing"


def test_lambda_has_required_properties():
    """Test that the Lambda function has the required properties."""
    with open(template_path, "r") as f:
        content = f.read()

    # Find the Lambda resource section
    lambda_section = re.search(
        r"AccessReviewLambda:.*?(?=\n\w+:|$)", content, re.DOTALL
    )
    assert lambda_section, "Lambda resource not found"

    lambda_content = lambda_section.group(0)
    assert (
        "Type: AWS::Lambda::Function" in lambda_content
    ), "Incorrect Lambda resource type"
    assert "Runtime:" in lambda_content, "Missing Runtime property"
    assert "Handler:" in lambda_content, "Missing Handler property"
    assert "Role:" in lambda_content, "Missing Role property"


def test_s3_bucket_has_required_properties():
    """Test that the S3 bucket has the required properties."""
    with open(template_path, "r") as f:
        content = f.read()

    # Find the S3 bucket resource section
    bucket_section = re.search(r"ReportBucket:.*?(?=\n\w+:|$)", content, re.DOTALL)
    assert bucket_section, "S3 bucket resource not found"

    bucket_content = bucket_section.group(0)
    assert (
        "Type: AWS::S3::Bucket" in bucket_content
    ), "Incorrect S3 bucket resource type"
    assert "Properties:" in bucket_content, "Missing Properties section"


def test_lambda_role_has_required_policies():
    """Test that the Lambda execution role has the required policies."""
    with open(template_path, "r") as f:
        content = f.read()

    # Find the IAM role resource section
    role_section = re.search(
        r"AccessReviewLambdaRole:.*?(?=\n\w+:|$)", content, re.DOTALL
    )
    assert role_section, "IAM role resource not found"

    role_content = role_section.group(0)
    assert "Type: AWS::IAM::Role" in role_content, "Incorrect IAM role resource type"
    assert (
        "AssumeRolePolicyDocument:" in role_content
    ), "Missing AssumeRolePolicyDocument"
    assert (
        "ManagedPolicyArns:" in role_content or "Policies:" in role_content
    ), "Missing policies"
