# AWS Access Review - Architecture

This document outlines the architecture of the AWS Access Review tool.

## System Components

### Lambda Function
The core of the solution is an AWS Lambda function that:
1. Collects security findings from various AWS services (IAM, Organizations, Security Hub, Access Analyzer, CloudTrail)
2. Analyzes these findings for security issues
3. Generates a comprehensive report
4. Uses Amazon Bedrock for AI-powered analysis of the findings
5. Delivers the report via email using SES

### AWS Services Integrated
- **IAM**: Analyzes roles, users, policies for security best practices
- **Organizations**: Reviews Service Control Policies (SCPs)
- **Security Hub**: Collects security findings from Security Hub
- **IAM Access Analyzer**: Identifies resources with external access
- **CloudTrail**: Verifies logging configuration
- **S3**: Stores reports
- **SES**: Delivers reports via email
- **Bedrock**: Provides AI analysis of findings

## Workflow
1. **Trigger**: Lambda is triggered manually or on a schedule
2. **Collection**: Lambda collects findings from all integrated services
3. **Analysis**: Findings are analyzed for security issues
4. **Report Generation**: 
   - A CSV report is generated with all findings
   - An AI-powered narrative is generated using Amazon Bedrock
5. **Delivery**: The report is stored in S3 and sent via email

## Security Considerations
- The Lambda execution role follows least privilege principles
- Report bucket has encryption enabled
- SES is configured for secure email delivery
- Temporary findings are not stored beyond the execution lifetime

## Deployment Architecture
- CloudFormation template provisions all required resources
- IAM roles and permissions are automatically configured
- S3 bucket for report storage is created with proper security settings
- Lambda is packaged with all dependencies