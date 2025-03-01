# AWS Access Review

An open-source tool for automated AWS security posture assessment and reporting.

## Overview

AWS Access Review is a lightweight, open-source tool deployable via a single CloudFormation template. It deploys a Lambda function that analyzes IAM policies, Resource Control Policies (RCPs), Service Control Policies (SCPs), Security Hub findings, IAM Access Analyzer results, and CloudTrail logs. The findings are processed by Amazon Bedrock's Titan model to generate a narrative analysis, which is emailed to stakeholders along with a CSV report of all findings.

## Features

- **Single-Click Deployment**: One CloudFormation template that creates all necessary resources
- **Comprehensive Security Analysis**: Reviews IAM policies, SCPs, RCPs, Security Hub findings, IAM Access Analyzer results, and CloudTrail logs
- **AI-Generated Narrative Reports**: Uses Amazon Bedrock Titan model to generate plain-language analysis
- **Automated Reporting**: Generates CSV report and emails findings with recommendations
- **Scheduled Execution**: Runs analyses on a configurable schedule

## Prerequisites

- AWS account with permissions to create CloudFormation stacks
- Organizations service (for SCP/RCP analysis, optional)
- Security Hub enabled (optional)
- IAM Access Analyzer enabled (optional)
- CloudTrail enabled (optional)
- Amazon Bedrock access with Titan model enabled
- Verified email address for SES (for sending reports)

## Installation

1. Clone this repository
2. Deploy the CloudFormation template:
   ```
   aws cloudformation deploy --template-file templates/access-review.yaml --stack-name aws-access-review --capabilities CAPABILITY_IAM --parameter-overrides RecipientEmail=your-email@example.com
   ```

## Testing

The project includes comprehensive tests for both the Python Lambda function and CloudFormation template.

### Prerequisites

- Python 3.8 or higher
- pip3

### Running Tests

To run all tests:

```bash
./run_tests.sh
```

To run only unit tests:

```bash
./run_tests.sh --unit
```

To run only CloudFormation template tests:

```bash
./run_tests.sh --cfn
```

To generate a coverage report:

```bash
./run_tests.sh --coverage
```

For more options:

```bash
./run_tests.sh --help
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

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

### 5. Success Metrics

- Successful deployment rate > 95%
- Detection of at least 95% of security issues found by native AWS services
- Analysis completion time < 5 minutes for standard accounts
- Positive GitHub feedback and community adoption
- User feedback rating on AI narrative quality > 4/5 