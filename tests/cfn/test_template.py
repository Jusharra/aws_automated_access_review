import os
import pytest
import yaml

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
    """Test that the CloudFormation template is valid YAML."""
    with open(template_path, "r") as f:
        try:
            yaml.safe_load(f)
        except yaml.YAMLError as e:
            pytest.fail(f"Template is not valid YAML: {e}")


def test_template_has_required_resources():
    """Test that the CloudFormation template has the required resources."""
    with open(template_path, "r") as f:
        template = yaml.safe_load(f)

    # Check for required resources
    resources = template.get("Resources", {})
    assert "AccessReviewLambda" in resources, "Lambda function resource is missing"
    assert "AccessReviewS3Bucket" in resources, "S3 bucket resource is missing"
    assert "AccessReviewLambdaRole" in resources, "Lambda execution role is missing"


def test_lambda_has_required_properties():
    """Test that the Lambda function has the required properties."""
    with open(template_path, "r") as f:
        template = yaml.safe_load(f)

    lambda_resource = template.get("Resources", {}).get("AccessReviewLambda", {})
    assert lambda_resource.get("Type") == "AWS::Lambda::Function"
    assert "Properties" in lambda_resource
    properties = lambda_resource.get("Properties", {})
    assert "Runtime" in properties
    assert "Handler" in properties
    assert "Role" in properties


def test_s3_bucket_has_required_properties():
    """Test that the S3 bucket has the required properties."""
    with open(template_path, "r") as f:
        template = yaml.safe_load(f)

    bucket_resource = template.get("Resources", {}).get("AccessReviewS3Bucket", {})
    assert bucket_resource.get("Type") == "AWS::S3::Bucket"
    assert "Properties" in bucket_resource


def test_lambda_role_has_required_policies():
    """Test that the Lambda execution role has the required policies."""
    with open(template_path, "r") as f:
        template = yaml.safe_load(f)

    role_resource = template.get("Resources", {}).get("AccessReviewLambdaRole", {})
    assert role_resource.get("Type") == "AWS::IAM::Role"
    assert "Properties" in role_resource
    properties = role_resource.get("Properties", {})
    assert "AssumeRolePolicyDocument" in properties
    assert "ManagedPolicyArns" in properties or "Policies" in properties
