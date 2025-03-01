import json
import boto3


def get_ai_analysis(bedrock_client, findings):
    """
    Main entry point for getting AI analysis of security findings.
    This function is called by the Lambda handler.

    Args:
        bedrock_client: Initialized Bedrock client
        findings (list): List of security findings

    Returns:
        str: AI-generated narrative summary
    """
    try:
        # Prepare the prompt for Claude model
        prompt = prepare_prompt(findings)

        # Call Bedrock with the Claude model
        response = invoke_claude_model(bedrock_client, prompt)

        # Extract and return the generated narrative
        return extract_narrative_claude(response)
    except Exception as e:
        print(f"Error generating narrative with Bedrock: {str(e)}")
        # Return a fallback narrative if Bedrock fails
        return generate_fallback_narrative()


def generate_narrative(findings):
    """
    Generate a narrative summary of security findings using Amazon Bedrock's Claude model.

    Args:
        findings (list): List of security findings

    Returns:
        str: AI-generated narrative summary
    """
    # Initialize Bedrock client
    bedrock = boto3.client("bedrock-runtime")

    # Call the main function
    return get_ai_analysis(bedrock, findings)


def prepare_prompt(findings):
    """
    Prepare a prompt for the Claude model based on the security findings.

    Args:
        findings (list): List of security findings

    Returns:
        str: Formatted prompt for the Claude model
    """
    # Count findings by severity
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    for finding in findings:
        if finding.get("severity") in severity_counts:
            severity_counts[finding.get("severity")] += 1

    # Group findings by category
    findings_by_category = {}
    for finding in findings:
        category = finding.get("category", "Other")
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)

    # Create a summary of findings for the prompt
    findings_summary = []
    for category, category_findings in findings_by_category.items():
        findings_summary.append(f"\nCategory: {category}")
        # Sort by severity (Critical first)
        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
            "Informational": 4,
        }
        sorted_findings = sorted(
            category_findings,
            key=lambda x: severity_order.get(x.get("severity", "Low"), 999),
        )

        for finding in sorted_findings[:5]:  # Limit to 5 findings per category
            summary = (
                f"  - {finding.get('severity')}: {finding.get('description')} "
                f"({finding.get('resource_type')}: {finding.get('resource_id')})"
            )
            findings_summary.append(summary)
        if len(category_findings) > 5:
            findings_summary.append(
                f"  - ... and {len(category_findings) - 5} more {category} findings"
            )

    # Construct the prompt for Claude
    prompt = f"""<findings>
# AWS Security Findings Summary

Total findings: {len(findings)}
- Critical: {severity_counts['Critical']}
- High: {severity_counts['High']}
- Medium: {severity_counts['Medium']}
- Low: {severity_counts['Low']}
- Informational: {severity_counts['Informational']}

## Findings by Category:
{chr(10).join(findings_summary)}
</findings>
"""

    return prompt


def invoke_claude_model(bedrock, prompt):
    """
    Invoke the Amazon Claude model via Bedrock.
    Args:
        bedrock: Initialized Bedrock client
        prompt: The prompt to send to the model
    Returns:
        dict: The model's response
    """
    # Model parameters
    model_id = "anthropic.claude-v2"  # Use the appropriate model ID
    # Request body
    request_body = {
        "prompt": (
            "\n\nHuman: You are a cybersecurity expert analyzing AWS security findings. "
            "Generate a concise, professional security report based on the following "
            f"findings:\n\n{prompt}\n\n"
            "Your report should include:\n"
            "1. An executive summary of the security posture\n"
            "2. Analysis of the most critical findings\n"
            "3. Clear, actionable recommendations\n"
            "4. Compliance implications\n\n"
            "Format the report with clear headings and concise language suitable for both "
            "technical and non-technical stakeholders.\n\n"
            "Assistant: I'll analyze the findings and provide a comprehensive security "
            "report.\n\n"
        ),
        "max_tokens_to_sample": 4096,
        "temperature": 0.7,
        "top_p": 0.9,
    }
    # Invoke the model
    response = bedrock.invoke_model(
        modelId=model_id,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )
    # Parse and return the response
    response_body = json.loads(response.get("body").read())
    return response_body


def extract_narrative_claude(response):
    """
    Extract the generated narrative from the Bedrock response.
    Args:
        response: The raw response from Bedrock
    Returns:
        str: The extracted narrative
    """
    try:
        # For Claude model
        narrative = response.get("completion", "")
        return narrative.strip()
    except Exception as e:
        print(f"Error extracting narrative from Bedrock response: {str(e)}")
        return generate_fallback_narrative()


def generate_fallback_narrative():
    """
    Generate a basic narrative if the AI model fails.
    Returns:
        str: A basic narrative summary
    """
    return (
        "AWS Access Review Report\n\n"
        "Due to technical limitations, a detailed AI analysis could not be generated. "
        "Please refer to the CSV report for a complete list of findings.\n\n"
        "Key Points:\n"
        "1. Review all findings marked as Critical or High priority first\n"
        "2. Address Medium priority findings as part of regular maintenance\n"
        "3. Consider Low priority findings for long-term security improvements\n"
        "4. Maintain regular security reviews and monitoring\n\n"
        "For detailed findings and recommendations, please consult the attached CSV report."
    )
