import json
import boto3
import os
import csv
import io
import datetime
import base64
import email.mime.multipart
import email.mime.text
import email.mime.application

def handler(event, context):
    """
    Main handler for the AWS Access Review Lambda function.
    Collects security findings from various AWS services and generates a report.
    """
    print("Starting AWS Access Review")
    
    # Get environment variables
    report_bucket = os.environ['REPORT_BUCKET']
    recipient_email = os.environ['RECIPIENT_EMAIL']
    
    # Initialize AWS clients
    iam = boto3.client('iam')
    try:
        org = boto3.client('organizations')
    except Exception as e:
        print(f"Warning: Unable to initialize Organizations client: {str(e)}")
        org = None
    
    try:
        securityhub = boto3.client('securityhub')
    except Exception as e:
        print(f"Warning: Unable to initialize Security Hub client: {str(e)}")
        securityhub = None
    
    try:
        access_analyzer = boto3.client('accessanalyzer')
    except Exception as e:
        print(f"Warning: Unable to initialize Access Analyzer client: {str(e)}")
        access_analyzer = None
    
    cloudtrail = boto3.client('cloudtrail')
    bedrock = boto3.client('bedrock-runtime')
    s3 = boto3.client('s3')
    ses = boto3.client('ses')
    
    # Collect findings
    findings = []
    
    try:
        # Collect IAM findings
        iam_findings = collect_iam_findings(iam)
        findings.extend(iam_findings)
        
        # Collect SCP findings if Organizations is available
        if org:
            scp_findings = collect_scp_findings(org)
            findings.extend(scp_findings)
        
        # Collect Security Hub findings if available
        if securityhub:
            securityhub_findings = collect_securityhub_findings(securityhub)
            findings.extend(securityhub_findings)
        
        # Collect IAM Access Analyzer findings if available
        if access_analyzer:
            access_analyzer_findings = collect_access_analyzer_findings(access_analyzer)
            findings.extend(access_analyzer_findings)
        
        # Collect CloudTrail findings
        cloudtrail_findings = collect_cloudtrail_findings(cloudtrail)
        findings.extend(cloudtrail_findings)
        
        # Generate CSV report
        csv_buffer = io.StringIO()
        csv_writer = csv.DictWriter(
            csv_buffer,
            fieldnames=['id', 'category', 'severity', 'resource_type', 'resource_id', 
                       'description', 'recommendation', 'compliance', 'detection_date']
        )
        csv_writer.writeheader()
        for finding in findings:
            csv_writer.writerow(finding)
        
        # Upload CSV to S3
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        csv_key = f'reports/aws-access-review-{timestamp}.csv'
        s3.put_object(
            Bucket=report_bucket,
            Key=csv_key,
            Body=csv_buffer.getvalue(),
            ContentType='text/csv'
        )
        
        # Generate AI narrative using Bedrock
        narrative = generate_ai_narrative(bedrock, findings)
        
        # Send email with CSV attachment
        send_email_with_attachment(
            ses, 
            recipient_email, 
            narrative, 
            csv_buffer.getvalue(), 
            f'aws-access-review-{timestamp}.csv'
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps('AWS Access Review completed successfully')
        }
        
    except Exception as e:
        print(f"Error in AWS Access Review: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error: {str(e)}')
        }

def collect_iam_findings(iam):
    """
    Collect IAM-related security findings.
    """
    findings = []
    
    # TODO: Implement comprehensive IAM analysis
    
    # For now, just add a sample finding
    findings.append({
        'id': 'IAM-001',
        'category': 'IAM',
        'severity': 'Medium',
        'resource_type': 'IAM Role',
        'resource_id': 'sample-role',
        'description': 'This is a sample IAM finding for demonstration purposes',
        'recommendation': 'No action needed, this is just a sample',
        'compliance': 'CIS 1.2',
        'detection_date': datetime.datetime.now().isoformat()
    })
    
    return findings

def collect_scp_findings(org):
    """
    Collect SCP-related security findings.
    """
    findings = []
    
    # TODO: Implement SCP analysis
    
    # For now, just add a sample finding
    findings.append({
        'id': 'SCP-001',
        'category': 'SCP',
        'severity': 'Low',
        'resource_type': 'Service Control Policy',
        'resource_id': 'sample-scp',
        'description': 'This is a sample SCP finding for demonstration purposes',
        'recommendation': 'No action needed, this is just a sample',
        'compliance': 'AWS Best Practices',
        'detection_date': datetime.datetime.now().isoformat()
    })
    
    return findings

def collect_securityhub_findings(securityhub):
    """
    Collect IAM-related findings from Security Hub.
    """
    findings = []
    
    # TODO: Implement Security Hub findings collection
    
    # For now, just add a sample finding
    findings.append({
        'id': 'SH-001',
        'category': 'Security Hub',
        'severity': 'High',
        'resource_type': 'IAM User',
        'resource_id': 'sample-user',
        'description': 'This is a sample Security Hub finding for demonstration purposes',
        'recommendation': 'No action needed, this is just a sample',
        'compliance': 'CIS 1.3',
        'detection_date': datetime.datetime.now().isoformat()
    })
    
    return findings

def collect_access_analyzer_findings(access_analyzer):
    """
    Collect findings from IAM Access Analyzer.
    """
    findings = []
    
    # TODO: Implement IAM Access Analyzer findings collection
    
    # For now, just add a sample finding
    findings.append({
        'id': 'AA-001',
        'category': 'Access Analyzer',
        'severity': 'Critical',
        'resource_type': 'S3 Bucket',
        'resource_id': 'sample-bucket',
        'description': 'This is a sample Access Analyzer finding for demonstration purposes',
        'recommendation': 'No action needed, this is just a sample',
        'compliance': 'AWS Best Practices',
        'detection_date': datetime.datetime.now().isoformat()
    })
    
    return findings

def collect_cloudtrail_findings(cloudtrail):
    """
    Analyze CloudTrail logs for suspicious activity.
    """
    findings = []
    
    # TODO: Implement CloudTrail log analysis
    
    # For now, just add a sample finding
    findings.append({
        'id': 'CT-001',
        'category': 'CloudTrail',
        'severity': 'Medium',
        'resource_type': 'IAM Role',
        'resource_id': 'sample-role',
        'description': 'This is a sample CloudTrail finding for demonstration purposes',
        'recommendation': 'No action needed, this is just a sample',
        'compliance': 'AWS Best Practices',
        'detection_date': datetime.datetime.now().isoformat()
    })
    
    return findings

def generate_ai_narrative(bedrock, findings):
    """
    Generate a narrative summary of findings using Amazon Bedrock.
    """
    # TODO: Implement actual Bedrock integration
    
    # For now, return a placeholder narrative
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
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
    
    narrative = f"""
    AWS Access Review Report - {timestamp}
    
    EXECUTIVE SUMMARY
    This is a placeholder for the AI-generated narrative that will be created using Amazon Bedrock.
    In the actual implementation, this will contain a detailed analysis of the security findings.
    
    FINDINGS SUMMARY
    Total findings: {len(findings)}
    Critical: {severity_counts['Critical']}
    High: {severity_counts['High']}
    Medium: {severity_counts['Medium']}
    Low: {severity_counts['Low']}
    
    For detailed findings, please see the attached CSV report.
    """
    
    return narrative

def send_email_with_attachment(ses, recipient, narrative, csv_data, csv_filename):
    """
    Send an email with the narrative and CSV attachment.
    """
    # TODO: Implement actual email sending with attachment
    
    print(f"Would send email to {recipient} with narrative and CSV attachment")
    
    # For now, just print the narrative
    print("Narrative:")
    print(narrative) 