[![Tests](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml/badge.svg)](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml)

# AWS Automated Access Review
## A Professional IAM Security Automation Tool

[![Tests](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml/badge.svg)](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml)

A comprehensive tool for automating AWS IAM security reviews. This project provides security professionals and GRC teams with automated access auditing capabilities to enhance cloud security posture and support compliance requirements. Use this tool to develop your portfolio while gaining practical cloud security skills.

> **⚠️ DISCLAIMER**: This tool is provided as-is without warranty of any kind. While it has been tested in development environments, thorough validation is required before deploying in production. Always review the code, test in a non-production environment first, and ensure it meets your organization's security requirements and compliance standards.

## Key Benefits

- **Enhanced Security Posture**: Systematically identify and remediate IAM security risks.
- **Professional Reporting**: Generate comprehensive reports for stakeholders and auditors.
- **GRC Expertise Development**: Build practical skills in governance, risk, and compliance.
- **Cloud Automation Experience**: Gain hands-on experience with Lambda and Bedrock integration.

## Skills Development Opportunities

1. **IAM Security Expertise**: Understand AWS access controls and identify common misconfigurations.
2. **Compliance Reporting**: Create actionable security reports for stakeholders and auditors.
3. **AI Integration**: Leverage Amazon Bedrock to transform raw security data into actionable insights.
4. **Serverless Architecture**: Deploy and manage cloud-native security automation tools.

## About

AWS Access Review is a comprehensive, zero-configuration security assessment tool that automatically evaluates your AWS environment for potential security risks and compliance gaps. Built for security professionals and GRC teams, it combines findings from multiple AWS security services into a clear, actionable report with AI-powered analysis.

Unlike complex security dashboards that require constant monitoring, AWS Access Review delivers insights directly to stakeholders' inboxes on a scheduled basis. The tool focuses on identifying IAM misconfigurations, overly permissive permissions, missing security controls, and external access risks—the most common sources of cloud security incidents.

With single-click deployment and integration with native AWS services, you can start receiving detailed security reports in minutes without extensive setup or third-party dependencies.

### Compliance Use Case: SOC 2 Type 2 Audits

Perfect for GRC professionals managing SOC 2 Type 2 and similar compliance frameworks. The tool:

- Runs monthly access reviews automatically (default: every 30 days)
- Creates detailed, timestamped reports for audit evidence
- Integrates with compliance workflows:
  1. Receive monthly reports via email
  2. Store reports as audit evidence
  3. Present to auditors when they sample specific months during assessment

## Core Features

- **IAM Security Auditing**: Identify MFA gaps and excessive permissions through detailed CSV reports.
- **Security Hub Integration**: Consolidate and summarize security findings from AWS Security Hub.
- **External Access Analysis**: Detect public resource exposure using IAM Access Analyzer.
- **AI-Powered Reporting**: Transform raw security data into readable, actionable insights with Amazon Bedrock.
- **Automated Email Delivery**: Receive comprehensive security reports directly to designated inbox.
- **Scheduled Execution**: Configure automatic security assessments at your preferred intervals.

*Note*: This project is under active development with ongoing enhancements planned.

## Key Deliverables

1. **IAM Compliance Report**: Comprehensive CSV listing of security findings with severity ratings.
   - Example: See `examples/sample-access-report.csv`.
2. **Executive Summary**: AI-generated narrative analysis of key security risks and remediation recommendations.
3. **Implementation Documentation**: Technical documentation of deployment architecture and configuration.

## Prerequisites

- AWS CLI installed and configured with appropriate permissions
- Python 3.11 or higher
- An AWS account with the following services enabled:
  - AWS Security Hub
  - IAM Access Analyzer
  - Amazon SES (with verified email for receiving reports)
  - Amazon Bedrock (with access to Claude model)

## Quick Start Guide

1. **Email Configuration**: Verify an email address in SES (approximately 5 minutes, see [detailed guide](docs/email-setup.md)).
2. **Deployment**: Execute the deployment command from [deployment documentation](docs/deployment.md) to provision resources.
3. **Initial Report**: Generate your first security assessment report to receive a CSV and executive summary.

### Detailed Setup Steps

1. Clone this repository:
   ```
   git clone https://github.com/ajy0127/aws_automated_access_review.git
   cd aws_automated_access_review
   ```

2. Check your AWS credentials and required services:
   ```
   ./scripts/check_aws_creds.sh
   ```
   
   You can specify an AWS profile:
   ```
   ./scripts/check_aws_creds.sh --profile your-aws-profile
   ```

3. Run the deployment script:
   ```
   ./scripts/deploy.sh --email your.email@example.com
   ```

   Additional options:
   - `--stack-name`: Custom CloudFormation stack name (default: aws-access-review)
   - `--region`: AWS region for deployment (default: us-east-1)
   - `--schedule`: Schedule expression for running the review (default: rate(30 days))
   - `--profile`: AWS CLI profile to use for credentials (default: uses default profile)

4. **⚠️ IMPORTANT: Verify your email address by clicking the link in the verification email sent by AWS SES before proceeding!**

5. Run an immediate access review report:
   ```
   ./scripts/run_report.sh
   ```
   
   You can specify the same options as with the deployment script:
   ```
   ./scripts/run_report.sh --stack-name your-stack-name --region your-region --profile your-aws-profile
   ```

## Cost & Scale Estimates

- Expected cost: Approximately $1/week in us-east-1 for a typical account.
- Scale: Successfully tested with AWS accounts containing up to 2000 resources and 500 IAM entities.
- Resource usage: Minimal; Lambda execution typically completes within 2-3 minutes.

## How It Works

1. The Lambda function runs on the configured schedule
2. It collects security findings from multiple AWS services
3. Amazon Bedrock generates a narrative summary of the findings
4. A detailed report is stored in S3 and sent via email
5. The report categorizes findings by severity and provides recommendations

### Sample Report Output

```
## AWS Access Review Summary - March 1, 2025

### Executive Summary
Your AWS environment has 17 security findings across 3 categories. Most critical: 2 IAM users with overly permissive policies and 1 S3 bucket with public access.

### Critical Findings
- Two admin IAM users are missing MFA: `admin-user1`, `dev-admin`
- S3 bucket `customer-data-bucket-prod` allows public read access
- Root account access key is active (should be removed immediately)

### Recommendations
1. Enable MFA for all admin users (priority: HIGH)
2. Remove public access from S3 bucket `customer-data-bucket-prod`
3. Delete root account access key
4. Review and prune unused IAM roles (5 roles unused for >90 days)

Full details in the attached CSV report.
```

The email includes both this readable summary and a detailed CSV with all findings.

## Running Reports

The AWS Access Review tool runs automatically according to the schedule you specified during deployment (default: monthly). However, you can also trigger a report manually:

1. Using the provided script:
   ```
   ./scripts/run_report.sh --profile your-aws-profile
   ```
   
   This script will:
   - Find your Lambda function from the CloudFormation stack
   - Invoke it with an empty event payload
   - Provide a link to CloudWatch logs for monitoring progress

2. Using the AWS Console:
   - Navigate to the Lambda console
   - Find the function named `<stack-name>-access-review`
   - Click "Test" and use an empty event `{}`
   
3. Using the AWS CLI directly:
   ```
   aws lambda invoke --function-name <stack-name>-access-review --payload '{}' response.json --profile your-aws-profile
   ```

Reports are sent to the email address you specified during deployment and are also stored in the S3 bucket created by the CloudFormation stack.

## Testing Locally

You can test the Lambda function locally before deploying to AWS:

```bash
# Basic usage (will prompt for email and bucket)
python -m src.cli.local_runner

# Specify email and bucket on command line
python -m src.cli.local_runner --email your.email@example.com

# Use a specific AWS profile (set before running)
AWS_PROFILE=your-aws-profile python -m src.cli.local_runner
```

Available options:
- `--email`: Recipient email address
- `--bucket`: S3 bucket name for reports (optional)
- `--profile`: AWS profile to use for credentials

## Customization

Adapt the solution to your specific requirements:
- **Report Customization**: Modify `src/lambda/index.py` to adjust security assessment criteria and outputs.
- **Email Templates**: Enhance email delivery formats through the `deploy.sh` templates.
- **Portfolio Enhancement**: Document your implementation and customizations to showcase your security automation expertise.

### Technical Customization Details

You can customize the tool by modifying the following files:
- `src/lambda/index.py`: Main Lambda function code
- `src/lambda/bedrock_integration.py`: Amazon Bedrock integration
- `templates/access-review-real.yaml`: CloudFormation template

## Frequently Asked Questions

### Access and Prerequisites

- **Q: What if I don't have access to Amazon Bedrock?**  
  A: The tool will still work, but without AI-powered summaries. Reports will contain raw findings only. Enable Security Hub and IAM Access Analyzer for best results.

- **Q: Can I use this in multiple AWS accounts?**  
  A: Yes! Deploy the solution in each account or use AWS Organizations with Security Hub aggregation.

- **Q: How do I change the report schedule after deployment?**  
  A: Update the CloudWatch Events rule in the AWS Console or redeploy with a new `--schedule` parameter.

- **Q: Will this work in any AWS region?**  
  A: Yes, but Amazon Bedrock is only available in select regions. Deploy in us-east-1, us-west-2, or other Bedrock-supported regions for full functionality.

## Troubleshooting

### AWS Credentials

- **"Unable to locate credentials"**: Configure your AWS credentials using `aws configure` or specify a profile with `--profile`
- **"The config profile could not be found"**: Check available profiles with `aws configure list-profiles`
- **"Access denied"**: Ensure your AWS credentials have the necessary permissions

### Email Verification

- **Email not received**: Verify that your email address is verified in Amazon SES
  - Check your CloudFormation stack outputs for the recipient email
  - Verify the email in the SES console: https://console.aws.amazon.com/ses/home#verified-senders-email
  - Check your spam folder for the verification email

### Lambda Function

- **Lambda execution errors**: Check CloudWatch Logs for the Lambda function
  - Navigate to CloudWatch Logs in the AWS Console
  - Look for the log group named `/aws/lambda/<stack-name>-access-review`
  - Review the most recent log stream for errors

### AWS Services

- **Missing findings**: Ensure that Security Hub and IAM Access Analyzer are enabled
  - Security Hub: https://console.aws.amazon.com/securityhub/
  - IAM Access Analyzer: https://console.aws.amazon.com/iam/home#/access-analyzer
- **Bedrock or SES failures**: Check if services are properly configured or if quotas are exceeded

### Running Reports

- **"Could not find Lambda function ARN"**: Verify your stack name with `aws cloudformation list-stacks`
- **Lambda invocation fails**: Check that your IAM role has permission to invoke Lambda functions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributions Welcome

Have suggestions for improvements? Encountered an issue? Interested in collaborating on GRC automation? Connect on [LinkedIn](https://www.linkedin.com/in/ajyawn/) or submit your feedback through GitHub Issues. This project is under active development and contributions are appreciated.

## Authors

See the AUTHORS.md file for a list of contributors to this project.

## Related Projects

Explore additional cloud security automation tools:  
- [Security Hub Compliance Analyzer](https://github.com/ajy0127/security-hub-compliance-analyzer): Multi-framework compliance monitoring tool with SOC 2 and NIST 800-53 cATO capabilities.

## Product Requirements Document

### 1. Product Vision

A simple, zero-configuration tool that automatically analyzes AWS security posture and delivers actionable insights directly to stakeholders' inboxes, with no dashboards or complex interfaces to maintain.

### 2. Target Users

- AWS administrators managing single or multi-account environments
- Security engineers conducting periodic access reviews
- DevOps teams implementing least-privilege security practices
- Organizations requiring evidence of security controls for compliance

### 3. Core Features

#### 3.1 Single-Click Deployment
- One CloudFormation template that creates all necessary resources
- Minimal configuration required (just email recipient)
- Self-contained with dependencies only on AWS native services

#### 3.2 Comprehensive Security Analysis
- Evaluate IAM policies for security best practices
- Review Service Control Policies (SCPs) across the organization
- Analyze Resource Control Policies (RCPs) for compliance
- Import Security Hub IAM findings
- Incorporate IAM Access Analyzer results
- Analyze CloudTrail logs for suspicious activity

#### 3.3 AI-Generated Narrative Reports
- Use Amazon Bedrock Titan model to generate plain-language analysis
- Provide executive summary of security posture
- Highlight critical findings with context and impact
- Generate specific remediation recommendations

#### 3.4 Automated Reporting
- Generate comprehensive CSV report of all findings
- Email delivery of narrative and CSV attachment
- S3 backup of all reports for historical reference

#### 3.5 Scheduled Execution
- Run analyses on a configurable schedule (default: weekly)
- Option for on-demand execution

### 4. Technical Architecture

#### 4.1 AWS Components
- **Lambda Function**: Core analysis engine and integrations
- **S3 Bucket**: Report storage
- **CloudWatch Events**: Scheduling
- **IAM Roles**: Least-privilege permissions for operation
- **SNS/SES**: Email delivery
- **Amazon Bedrock**: AI-generated narrative using Titan model

#### 4.2 Workflow
1. CloudWatch scheduled event triggers Lambda function
2. Lambda collects data from:
   - IAM (policies, roles, users)
   - Organizations (SCPs, RCPs)
   - Security Hub IAM findings
   - IAM Access Analyzer results
   - CloudTrail logs
3. Lambda processes findings and generates structured data
4. Lambda sends structured findings to Amazon Bedrock
5. Bedrock Titan model generates natural language narrative and recommendations
6. Lambda generates CSV report of all findings
7. Lambda uploads CSV to S3 and sends email with narrative and CSV attachment

## Development

### Project Structure

```
aws_access_review/
├── src/                      # All source code
│   ├── lambda/               # Lambda function code
│   │   ├── __init__.py
│   │   ├── index.py          # Main Lambda handler
│   │   └── bedrock_integration.py
│   └── cli/                  # CLI tools and scripts
│       ├── __init__.py
│       └── local_runner.py   # For local executions
│
├── scripts/                  # Shell scripts for various tasks
│   ├── deploy.sh             # Deployment script
│   ├── run_report.sh         # Run reports
│   ├── run_tests.sh          # Run tests 
│   ├── check_aws_creds.sh    # Credential checker
│   ├── cleanup.sh            # Resource cleanup
│   └── setup_dev.sh          # Dev environment setup
│
├── tests/                    # All test files
│   ├── unit/                 # Unit tests
│   │   ├── test_handler.py
│   │   └── test_bedrock_integration.py
│   ├── integration/          # Integration tests if needed
│   ├── cfn/                  # CloudFormation tests
│   │   └── test_template.py
│   └── style/                # Code style tests
│       └── test_code_style.py
│
├── templates/                # CloudFormation templates
│   ├── access-review.yaml
│   └── access-review-real.yaml
│
├── docs/                     # Documentation
│   ├── implementation_plan.md
│   ├── architecture.md       # System architecture docs
│   └── usage.md              # Detailed usage instructions
```

### Setting Up a Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/ajy0127/aws_automated_access_review.git
   cd aws_automated_access_review
   ```

2. Use the setup script to create a development environment:
   ```bash
   ./scripts/setup_dev.sh
   ```
   
   This will:
   - Create a virtual environment
   - Install dependencies
   - Set up mock AWS credentials
   - Run basic tests

3. Alternatively, set up manually:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

### Code Style

This project follows strict code style guidelines:

- We use [Black](https://black.readthedocs.io/) for code formatting
- We use [Flake8](https://flake8.pycqa.org/) for style enforcement
- Maximum line length is set to 100 characters

To check code style:
```bash
flake8 src/ tests/
black --check src/ tests/
```

To automatically format code:
```bash
black src/ tests/
```

## Testing

The project includes comprehensive tests for both the Python Lambda function and CloudFormation template.

### Prerequisites

- Python 3.8 or higher
- pip3

### Running Tests

To run all tests:

```bash
./scripts/run_tests.sh
```

To run only unit tests:

```bash
./scripts/run_tests.sh --unit
```

To run only CloudFormation template tests:

```bash
./scripts/run_tests.sh --cfn
```

To generate a coverage report:

```bash
./scripts/run_tests.sh --coverage
```

For more options:

```bash
./scripts/run_tests.sh --help
```
