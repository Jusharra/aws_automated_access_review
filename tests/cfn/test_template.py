import os
import pytest
import cfnlint.core
from pathlib import Path
import subprocess
import json

@pytest.fixture
def template_path():
    """Path to the CloudFormation template."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                        'templates', 'access-review.yaml')

def test_cfn_lint(template_path):
    """Test the CloudFormation template with cfn-lint."""
    # Verify the template file exists
    assert os.path.isfile(template_path), f"Template file not found: {template_path}"
    
    # Run cfn-lint using subprocess to avoid API changes
    cmd = ['cfn-lint', '--format', 'json', template_path]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # If there are errors, the output will be in JSON format
    if result.returncode != 0:
        try:
            errors = json.loads(result.stdout)
            # Filter out informational messages (level might be string or int)
            # Level values: 'informational'=0, 'warning'=1, 'error'=2
            error_messages = []
            for error in errors:
                level = error.get('Level', '')
                # Skip informational messages
                if level == 'informational':
                    continue
                error_messages.append(f"{error.get('Rule', '')}: {error.get('Message', '')} (Line: {error.get('Location', {}).get('Start', {}).get('LineNumber', 'N/A')})")
            
            assert len(error_messages) == 0, f"CloudFormation template validation failed with {len(error_messages)} issues:\n" + "\n".join(error_messages)
        except json.JSONDecodeError:
            # If not JSON, just print the output
            assert result.returncode == 0, f"CloudFormation template validation failed:\n{result.stdout}\n{result.stderr}"
    
    # If we got here, the template passed validation

def test_template_parameters():
    """Test the CloudFormation template parameters."""
    # Load the template
    template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                'templates', 'access-review.yaml')
    
    with open(template_path, 'r') as f:
        template_content = f.read()
    
    # Check for required parameters
    assert 'RecipientEmail' in template_content, "Required parameter 'RecipientEmail' not found in template"
    assert 'ScheduleExpression' in template_content, "Parameter 'ScheduleExpression' not found in template"
    assert 'ReportBucketName' in template_content, "Parameter 'ReportBucketName' not found in template"

def test_template_resources():
    """Test the CloudFormation template resources."""
    # Load the template
    template_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                'templates', 'access-review.yaml')
    
    with open(template_path, 'r') as f:
        template_content = f.read()
    
    # Check for required resources
    required_resources = [
        'ReportBucket',
        'AccessReviewLambdaRole',
        'AccessReviewLambda',
        'ScheduledRule',
        'PermissionForEventsToInvokeLambda'
    ]
    
    for resource in required_resources:
        assert resource in template_content, f"Required resource '{resource}' not found in template"
    
    # Check for IAM permissions
    required_permissions = [
        's3:PutObject',
        'iam:GetPolicy',
        'organizations:DescribeOrganization',
        'securityhub:GetFindings',
        'access-analyzer:ListAnalyzers',
        'cloudtrail:LookupEvents',
        'bedrock:InvokeModel',
        'ses:SendEmail'
    ]
    
    for permission in required_permissions:
        assert permission in template_content, f"Required IAM permission '{permission}' not found in template" 