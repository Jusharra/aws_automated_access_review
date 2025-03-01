import json
import boto3

def generate_narrative(findings):
    """
    Generate a narrative summary of security findings using Amazon Bedrock's Titan model.
    
    Args:
        findings (list): List of security findings
        
    Returns:
        str: AI-generated narrative summary
    """
    # Initialize Bedrock client
    bedrock = boto3.client('bedrock-runtime')
    
    # Prepare the prompt for Titan model
    prompt = prepare_prompt(findings)
    
    try:
        # Call Bedrock with the Titan model
        response = invoke_titan_model(bedrock, prompt)
        
        # Extract and return the generated narrative
        return extract_narrative(response)
    except Exception as e:
        print(f"Error generating narrative with Bedrock: {str(e)}")
        # Return a fallback narrative if Bedrock fails
        return generate_fallback_narrative(findings)

def prepare_prompt(findings):
    """
    Prepare a prompt for the Titan model based on the security findings.
    
    Args:
        findings (list): List of security findings
        
    Returns:
        str: Formatted prompt for the Titan model
    """
    # Count findings by severity
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    for finding in findings:
        if finding['severity'] in severity_counts:
            severity_counts[finding['severity']] += 1
    
    # Group findings by category
    findings_by_category = {}
    for finding in findings:
        category = finding['category']
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)
    
    # Create a summary of findings for the prompt
    findings_summary = []
    for category, category_findings in findings_by_category.items():
        findings_summary.append(f"Category: {category}")
        for finding in category_findings[:3]:  # Limit to 3 findings per category to keep prompt size reasonable
            findings_summary.append(f"  - {finding['severity']}: {finding['description']}")
        if len(category_findings) > 3:
            findings_summary.append(f"  - ... and {len(category_findings) - 3} more {category} findings")
    
    # Construct the prompt
    prompt = f"""
You are a cybersecurity expert analyzing AWS security findings. Generate a concise, professional security report based on the following findings:

Summary:
- Total findings: {len(findings)}
- Critical: {severity_counts['Critical']}
- High: {severity_counts['High']}
- Medium: {severity_counts['Medium']}
- Low: {severity_counts['Low']}

Findings:
{chr(10).join(findings_summary)}

Your report should include:
1. An executive summary of the security posture
2. Analysis of the most critical findings
3. Clear, actionable recommendations
4. Compliance implications

Format the report with clear headings and concise language suitable for both technical and non-technical stakeholders.
"""
    
    return prompt

def invoke_titan_model(bedrock, prompt):
    """
    Invoke the Amazon Titan model via Bedrock.
    
    Args:
        bedrock: Bedrock client
        prompt (str): The prompt to send to the model
        
    Returns:
        dict: The raw response from Bedrock
    """
    # Model parameters
    model_id = "amazon.titan-text-express-v1"  # Use the appropriate model ID
    
    # Request body
    request_body = {
        "inputText": prompt,
        "textGenerationConfig": {
            "maxTokenCount": 4096,
            "temperature": 0.7,
            "topP": 0.9,
            "stopSequences": []
        }
    }
    
    # Invoke the model
    response = bedrock.invoke_model(
        modelId=model_id,
        body=json.dumps(request_body)
    )
    
    # Parse and return the response
    response_body = json.loads(response.get('body').read())
    return response_body

def extract_narrative(response):
    """
    Extract the generated narrative from the Bedrock response.
    
    Args:
        response (dict): The raw response from Bedrock
        
    Returns:
        str: The extracted narrative text
    """
    # Extract the generated text from the response
    # The exact structure depends on the model used
    try:
        # For Titan model
        narrative = response.get('results', [{}])[0].get('outputText', '')
        return narrative.strip()
    except (KeyError, IndexError) as e:
        print(f"Error extracting narrative from response: {str(e)}")
        return "Error generating narrative. Please check the CSV report for findings."

def generate_fallback_narrative(findings):
    """
    Generate a basic narrative without using Bedrock, as a fallback.
    
    Args:
        findings (list): List of security findings
        
    Returns:
        str: A basic narrative summary
    """
    # Count findings by severity
    severity_counts = {
        'Critical': 0,
        'High': 0,
        'Medium': 0,
        'Low': 0
    }
    
    for finding in findings:
        if finding['severity'] in severity_counts:
            severity_counts[finding['severity']] += 1
    
    # Find the most critical findings
    critical_findings = [f for f in findings if f['severity'] == 'Critical']
    high_findings = [f for f in findings if f['severity'] == 'High']
    
    # Generate a basic narrative
    narrative = f"""
AWS ACCESS REVIEW REPORT

EXECUTIVE SUMMARY
An automated security review of your AWS environment has identified {len(findings)} potential security issues.
This includes {severity_counts['Critical']} critical, {severity_counts['High']} high, {severity_counts['Medium']} medium, and {severity_counts['Low']} low severity findings.

CRITICAL FINDINGS
"""
    
    if critical_findings:
        for finding in critical_findings[:3]:  # Limit to 3 critical findings
            narrative += f"- {finding['resource_type']} ({finding['resource_id']}): {finding['description']}\n  Recommendation: {finding['recommendation']}\n\n"
        if len(critical_findings) > 3:
            narrative += f"- ... and {len(critical_findings) - 3} more critical findings\n\n"
    else:
        narrative += "No critical findings identified.\n\n"
    
    narrative += "HIGH SEVERITY FINDINGS\n"
    
    if high_findings:
        for finding in high_findings[:3]:  # Limit to 3 high findings
            narrative += f"- {finding['resource_type']} ({finding['resource_id']}): {finding['description']}\n  Recommendation: {finding['recommendation']}\n\n"
        if len(high_findings) > 3:
            narrative += f"- ... and {len(high_findings) - 3} more high severity findings\n\n"
    else:
        narrative += "No high severity findings identified.\n\n"
    
    narrative += """
RECOMMENDATIONS
1. Address all critical findings immediately
2. Schedule remediation for high severity findings
3. Review the complete CSV report for all findings

For detailed findings, please see the attached CSV report.
"""
    
    return narrative 