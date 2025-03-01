import json
import pytest
from unittest.mock import patch, MagicMock, mock_open

# Import the Bedrock integration module
import sys
sys.path.append('src/lambda')
import bedrock_integration

@pytest.fixture
def sample_findings():
    """Sample security findings for testing."""
    return [
        {
            'id': 'TEST-001',
            'category': 'IAM',
            'severity': 'Critical',
            'resource_type': 'IAM Role',
            'resource_id': 'test-role-1',
            'description': 'Test critical finding',
            'recommendation': 'Fix this critical issue',
            'compliance': 'CIS 1.1',
            'detection_date': '2023-01-01T00:00:00'
        },
        {
            'id': 'TEST-002',
            'category': 'IAM',
            'severity': 'High',
            'resource_type': 'IAM User',
            'resource_id': 'test-user-1',
            'description': 'Test high severity finding',
            'recommendation': 'Fix this high severity issue',
            'compliance': 'CIS 1.2',
            'detection_date': '2023-01-01T00:00:00'
        },
        {
            'id': 'TEST-003',
            'category': 'S3',
            'severity': 'Medium',
            'resource_type': 'S3 Bucket',
            'resource_id': 'test-bucket',
            'description': 'Test medium severity finding',
            'recommendation': 'Consider fixing this issue',
            'compliance': 'AWS Best Practices',
            'detection_date': '2023-01-01T00:00:00'
        }
    ]

def test_prepare_prompt(sample_findings):
    """Test the prompt preparation function."""
    prompt = bedrock_integration.prepare_prompt(sample_findings)
    
    # Verify the prompt contains key information
    assert 'Total findings: 3' in prompt
    assert 'Critical: 1' in prompt
    assert 'High: 1' in prompt
    assert 'Medium: 1' in prompt
    assert 'Category: IAM' in prompt
    assert 'Category: S3' in prompt
    assert 'Test critical finding' in prompt
    assert 'Test high severity finding' in prompt
    assert 'Test medium severity finding' in prompt

def test_invoke_titan_model():
    """Test the Titan model invocation function."""
    # Create a mock Bedrock client
    mock_bedrock = MagicMock()
    
    # Configure the mock response
    mock_response = {
        'body': MagicMock()
    }
    mock_response['body'].read.return_value = json.dumps({
        'results': [{'outputText': 'This is a test narrative.'}]
    })
    mock_bedrock.invoke_model.return_value = mock_response
    
    # Call the function
    response = bedrock_integration.invoke_titan_model(mock_bedrock, "Test prompt")
    
    # Verify the function called Bedrock with the right parameters
    mock_bedrock.invoke_model.assert_called_once()
    args, kwargs = mock_bedrock.invoke_model.call_args
    
    # Check that the model ID is correct
    assert kwargs['modelId'] == 'amazon.titan-text-express-v1'
    
    # Check that the request body contains the prompt
    request_body = json.loads(kwargs['body'])
    assert request_body['inputText'] == 'Test prompt'
    assert 'textGenerationConfig' in request_body
    
    # Verify the response is correctly parsed
    assert 'results' in response
    assert response['results'][0]['outputText'] == 'This is a test narrative.'

def test_extract_narrative():
    """Test the narrative extraction function."""
    # Test with a valid response
    valid_response = {
        'results': [{'outputText': 'This is a test narrative.'}]
    }
    narrative = bedrock_integration.extract_narrative(valid_response)
    assert narrative == 'This is a test narrative.'
    
    # Test with an invalid response
    invalid_response = {}
    narrative = bedrock_integration.extract_narrative(invalid_response)
    # The function might return an empty string or an error message
    # Let's check for both possibilities
    assert narrative == '' or 'Error generating narrative' in narrative

def test_generate_fallback_narrative(sample_findings):
    """Test the fallback narrative generation function."""
    narrative = bedrock_integration.generate_fallback_narrative(sample_findings)
    
    # Verify the narrative contains key information
    assert 'AWS ACCESS REVIEW REPORT' in narrative
    assert 'EXECUTIVE SUMMARY' in narrative
    assert '3 potential security issues' in narrative
    assert 'CRITICAL FINDINGS' in narrative
    assert 'HIGH SEVERITY FINDINGS' in narrative
    assert 'test-role-1' in narrative
    assert 'test-user-1' in narrative
    assert 'Fix this critical issue' in narrative
    assert 'RECOMMENDATIONS' in narrative

def test_generate_narrative_success(sample_findings):
    """Test the main narrative generation function with successful Bedrock call."""
    # Mock the Bedrock client and response
    with patch('boto3.client') as mock_client:
        # Configure the mock response
        mock_bedrock = MagicMock()
        mock_response = {
            'body': MagicMock()
        }
        mock_response['body'].read.return_value = json.dumps({
            'results': [{'outputText': 'This is a test narrative from Bedrock.'}]
        })
        mock_bedrock.invoke_model.return_value = mock_response
        mock_client.return_value = mock_bedrock
        
        # Call the function
        narrative = bedrock_integration.generate_narrative(sample_findings)
        
        # Verify the result
        assert narrative == 'This is a test narrative from Bedrock.'
        mock_bedrock.invoke_model.assert_called_once()

def test_generate_narrative_fallback(sample_findings):
    """Test the main narrative generation function with Bedrock failure."""
    # Mock the Bedrock client to raise an exception
    with patch('boto3.client') as mock_client:
        mock_bedrock = MagicMock()
        mock_bedrock.invoke_model.side_effect = Exception('Bedrock error')
        mock_client.return_value = mock_bedrock
        
        # Call the function
        narrative = bedrock_integration.generate_narrative(sample_findings)
        
        # Verify the fallback narrative was generated
        assert 'AWS ACCESS REVIEW REPORT' in narrative
        assert 'EXECUTIVE SUMMARY' in narrative
        assert '3 potential security issues' in narrative 