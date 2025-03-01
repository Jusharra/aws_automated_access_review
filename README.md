[![Tests](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml/badge.svg)](https://github.com/ajy0127/aws_automated_access_review/actions/workflows/tests.yml)

# AWS Automated Access Review

> **For GRC Professionals & Portfolio Building**: This tool is designed for Governance, Risk, and Compliance (GRC) professionals to use in their organizations and for security engineers building their portfolios in test AWS accounts.
>
> **⚠️ DISCLAIMER**: This tool is provided as-is without warranty of any kind. While it has been tested in development environments, thorough validation is required before deploying in production. Always review the code, test in a non-production environment first, and ensure it meets your organization's security requirements and compliance standards.

A comprehensive solution for automated AWS security posture assessment and reporting. This tool helps you maintain security best practices by regularly scanning your AWS environment for potential security issues and sending detailed reports.

## Features

- **IAM Security Assessment**: Identifies users without MFA, unused access keys, and overly permissive policies
- **Security Hub Integration**: Collects and summarizes findings from AWS Security Hub
- **IAM Access Analyzer**: Reports on resources with external access
- **AI-Powered Analysis**: Uses Amazon Bedrock to generate human-readable summaries of findings
- **Email Reporting**: Sends detailed reports with severity-based categorization
- **Scheduled Execution**: Runs automatically on a configurable schedule

## Prerequisites

- AWS CLI installed and configured with appropriate permissions
- Python 3.11 or higher
- An AWS account with the following services enabled:
  - AWS Security Hub
  - IAM Access Analyzer
  - Amazon SES (with verified email for receiving reports)
  - Amazon Bedrock (with access to Claude model)

## Deployment

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
   - `--schedule`: Schedule expression for running the review (default: rate(7 days))
   - `--profile`: AWS CLI profile to use for credentials (default: uses default profile)

4. Verify your email address by clicking the link in the verification email sent by AWS SES.

5. (Optional) Run an immediate access review report:
   ```
   ./scripts/run_report.sh
   ```
   
   You can specify the same options as with the deployment script:
   ```
   ./scripts/run_report.sh --stack-name your-stack-name --region your-region --profile your-aws-profile
   ```

## How It Works

1. The Lambda function runs on the configured schedule
2. It collects security findings from multiple AWS services
3. Amazon Bedrock generates a narrative summary of the findings
4. A detailed report is stored in S3 and sent via email
5. The report categorizes findings by severity and provides recommendations

## Running Reports

The AWS Access Review tool runs automatically according to the schedule you specified during deployment (default: weekly). However, you can also trigger a report manually:

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

You can customize the tool by modifying the following files:
- `src/lambda/index.py`: Main Lambda function code
- `src/lambda/bedrock_integration.py`: Amazon Bedrock integration
- `templates/access-review-real.yaml`: CloudFormation template

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

### Running Reports

- **"Could not find Lambda function ARN"**: Verify your stack name with `aws cloudformation list-stacks`
- **Lambda invocation fails**: Check that your IAM role has permission to invoke Lambda functions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

See the AUTHORS.md file for a list of contributors to this project.

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