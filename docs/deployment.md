# AWS Automated Access Review Deployment Guide

This guide will walk you through deploying the AWS Automated Access Review tool. A successful deployment is a portfolio-worthy accomplishment showing your ability to implement security monitoring solutions.

## Prerequisites

Before deployment, ensure you have:

1. **AWS Account**: An active AWS account with administrator privileges
2. **AWS CLI**: Installed and configured on your machine
3. **Python**: Version 3.11 or higher
4. **Verified Email**: Set up in AWS SES (see [Email Setup Guide](email-setup.md))
5. **Services Enabled**:
   - AWS Security Hub
   - IAM Access Analyzer
   - Amazon SES (with verified email)
   - Amazon Bedrock (for AI summaries)

## One-Command Deployment

The simplest way to deploy is using our deployment script:

```bash
./scripts/deploy.sh --email your.verified@email.com
```

This single command:
- Creates a CloudFormation stack using the `access-review-real.yaml` template
- Sets up IAM permissions using least-privilege principles
- Configures the Lambda function and scheduling
- Prepares S3 storage for reports
- Sets up email delivery through SES
- Packages and updates the Lambda function code after stack creation

### Deployment Options

You can customize your deployment:

```bash
./scripts/deploy.sh --email your.verified@email.com --stack-name portfolio-access-review --region us-east-1 --schedule "rate(30 days)" --profile your-aws-profile
```

Options explained:
- `--email`: Your verified SES email (required)
- `--stack-name`: Custom name for CloudFormation stack
- `--region`: AWS region for deployment
- `--schedule`: How often to run (CloudWatch schedule expression)
- `--profile`: AWS CLI profile to use

## Verifying Deployment

After running the deployment script:

1. Check the CloudFormation console to confirm stack creation
2. Verify Lambda function creation
3. Check S3 bucket exists for reports
4. Confirm CloudWatch Events rule is created with correct schedule

## Portfolio Showcase Elements

After deployment, capture these portfolio assets:

1. **CloudFormation Template**: Save a copy showing your infrastructure-as-code skills
2. **Deployment Log**: Record your deployment process for documentation
3. **Architecture Diagram**: Reference the diagram in the docs folder
4. **First Report**: Run an initial report using `./scripts/run_report.sh`

## Next Steps

1. Run your first report to test the setup
2. Document your deployment process
3. Set up a regular schedule to review the generated reports
4. Consider extending functionality with custom findings

## Troubleshooting

- **Stack creation failed?** Check CloudFormation events for detailed error messages
- **Lambda not running?** Verify IAM permissions and CloudWatch Events rule
- **No email received?** Confirm your email is verified in SES
- **Need more help?** Check the main README troubleshooting section