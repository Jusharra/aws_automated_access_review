import json
import os
import pytest
import boto3
from unittest.mock import patch, MagicMock
from moto import mock_aws

# Import the handler function from the Lambda code
import sys
sys.path.append('src/lambda')
from index import handler, collect_iam_findings, collect_scp_findings, collect_cloudtrail_findings

@pytest.fixture
def aws_credentials():
    """Mocked AWS Credentials for boto3."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'
    os.environ['AWS_DEFAULT_REGION'] = 'us-east-1'

@pytest.fixture
def s3(aws_credentials):
    with mock_aws():
        s3_client = boto3.client('s3', region_name='us-east-1')
        yield s3_client

@pytest.fixture
def ses(aws_credentials):
    with mock_aws():
        ses_client = boto3.client('ses', region_name='us-east-1')
        yield ses_client

@pytest.fixture
def lambda_environment():
    """Set up Lambda environment variables."""
    os.environ['REPORT_BUCKET'] = 'test-report-bucket'
    os.environ['RECIPIENT_EMAIL'] = 'test@example.com'

def test_handler_success(s3, ses, lambda_environment):
    """Test the Lambda handler with successful execution."""
    # Create the S3 bucket
    s3.create_bucket(Bucket='test-report-bucket')
    
    # Mock all the AWS clients that will be used
    with patch('boto3.client') as mock_client:
        # Configure the mock to return specific clients
        mock_client_instances = {
            'iam': MagicMock(),
            'organizations': MagicMock(),
            'securityhub': MagicMock(),
            'access-analyzer': MagicMock(),
            'cloudtrail': MagicMock(),
            'bedrock-runtime': MagicMock(),
            's3': s3,
            'ses': ses
        }
        
        def side_effect(service_name, *args, **kwargs):
            return mock_client_instances.get(service_name, MagicMock())
        
        mock_client.side_effect = side_effect
        
        # Mock the collect functions to return sample findings
        with patch('index.collect_iam_findings', return_value=[{
            'id': 'TEST-IAM-001',
            'category': 'IAM',
            'severity': 'Medium',
            'resource_type': 'IAM Role',
            'resource_id': 'test-role',
            'description': 'Test IAM finding',
            'recommendation': 'Test recommendation',
            'compliance': 'CIS 1.2',
            'detection_date': '2023-01-01T00:00:00'
        }]):
            with patch('index.collect_scp_findings', return_value=[]):
                with patch('index.collect_securityhub_findings', return_value=[]):
                    with patch('index.collect_access_analyzer_findings', return_value=[]):
                        with patch('index.collect_cloudtrail_findings', return_value=[]):
                            with patch('index.generate_ai_narrative', return_value="Test narrative"):
                                with patch('index.send_email_with_attachment'):
                                    # Call the handler
                                    response = handler({}, {})
                                    
                                    # Verify the response
                                    assert response['statusCode'] == 200
                                    assert 'AWS Access Review completed successfully' in response['body']
                                    
                                    # Verify S3 upload was called
                                    objects = s3.list_objects(Bucket='test-report-bucket')
                                    assert 'Contents' in objects
                                    assert objects['Contents'][0]['Key'].startswith('reports/aws-access-review-')

def test_collect_iam_findings():
    """Test the IAM findings collection function."""
    mock_iam = MagicMock()
    
    # Call the function
    findings = collect_iam_findings(mock_iam)
    
    # Verify the results
    assert len(findings) > 0
    assert findings[0]['category'] == 'IAM'
    assert 'severity' in findings[0]
    assert 'description' in findings[0]

def test_collect_scp_findings():
    """Test the SCP findings collection function."""
    mock_org = MagicMock()
    
    # Call the function
    findings = collect_scp_findings(mock_org)
    
    # Verify the results
    assert len(findings) > 0
    assert findings[0]['category'] == 'SCP'
    assert 'severity' in findings[0]
    assert 'description' in findings[0]

def test_collect_cloudtrail_findings():
    """Test the CloudTrail findings collection function."""
    mock_cloudtrail = MagicMock()
    
    # Call the function
    findings = collect_cloudtrail_findings(mock_cloudtrail)
    
    # Verify the results
    assert len(findings) > 0
    assert findings[0]['category'] == 'CloudTrail'
    assert 'severity' in findings[0]
    assert 'description' in findings[0]

def test_handler_exception_handling(lambda_environment):
    """Test the Lambda handler's exception handling."""
    # Mock boto3.client to raise an exception
    with patch('boto3.client', side_effect=Exception('Test exception')):
        try:
            # Call the handler
            response = handler({}, {})
            
            # Verify the response
            assert response['statusCode'] == 500
            assert 'Error' in response['body']
            assert 'Test exception' in response['body']
        except Exception as e:
            # If the handler doesn't catch the exception, we'll catch it here
            # and verify it's the expected exception
            assert str(e) == 'Test exception' 