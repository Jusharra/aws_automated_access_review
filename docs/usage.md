# AWS Access Review - Usage Guide

This document provides detailed instructions for using the AWS Access Review tool.

## Deployment

### Using the Deployment Script
The easiest way to deploy the tool is using the provided deployment script:

```bash
./scripts/deploy.sh --email your.email@example.com
```

This script will:
1. Package the Lambda function
2. Deploy the CloudFormation stack
3. Configure the required permissions
4. Send a verification email to your provided address

**⚠️ IMPORTANT: You MUST verify your email address by clicking the link in the verification email sent by AWS SES before reports can be delivered!**

### Manual Deployment
If you prefer to deploy manually:

1. Package the Lambda function:
   ```bash
   pip install -r requirements.txt -t lambda_package/
   cp src/lambda/* lambda_package/
   cd lambda_package && zip -r ../lambda_function.zip . && cd ..
   ```

2. Deploy the CloudFormation template:
   ```bash
   aws cloudformation deploy \
     --template-file templates/access-review.yaml \
     --stack-name aws-access-review \
     --capabilities CAPABILITY_IAM \
     --parameter-overrides RecipientEmail=your-email@example.com
   ```

## Running an Access Review

### Via AWS Console
1. Navigate to the AWS Lambda console
2. Find the function named `aws-access-review-AwsAccessReviewLambda-*`
3. Click "Test" and optionally provide a test event with `recipient_email` or `force_real_execution` parameters
4. View the results in the CloudWatch logs or check your email for the report

### Using the CLI
You can trigger the Lambda function via AWS CLI:

```bash
aws lambda invoke \
  --function-name aws-access-review-AwsAccessReviewLambda-* \
  --payload '{"recipient_email":"your-email@example.com"}' \
  output.json
```

### Scheduling Regular Reviews
The tool is set to run monthly by default (every 30 days), which is ideal for compliance frameworks like SOC 2 Type 2 that require regular access reviews:

1. The CloudFormation template creates an EventBridge rule with the specified schedule
2. Default: `rate(30 days)` - perfect for monthly compliance reviews
3. Customize during deployment with the `--schedule` parameter:
   ```
   ./scripts/deploy.sh --email your.email@example.com --schedule "cron(0 8 1 * ? *)"
   ```
   This example runs at 8:00 AM UTC on the 1st day of each month

### Compliance Workflow Integration

For SOC 2 Type 2 and similar frameworks, follow this recommended workflow:

1. **Collect Evidence**: Save the monthly reports in your compliance documentation system
2. **Track Remediation**: Create tickets for each finding that requires action
3. **Document Actions**: Record all remediation steps taken
4. **Maintain History**: Keep all reports for the entire audit period (typically 12 months)
5. **Provide Samples**: When auditors request samples from specific months, provide the corresponding reports

## Interpreting Results

The Access Review generates two main outputs:
1. A CSV file with detailed findings
2. An email with an AI-generated narrative summary

### CSV Report Fields
- `id`: Unique identifier for the finding
- `category`: The category of the finding (IAM, CloudTrail, etc.)
- `severity`: How critical the finding is (Critical, High, Medium, Low, Informational)
- `resource_type`: The type of resource affected
- `resource_id`: The specific resource ID
- `description`: Detailed description of the finding
- `recommendation`: Suggested remediation steps
- `compliance`: Related compliance standards
- `detection_date`: When the issue was detected

### Narrative Summary
The AI-generated narrative includes:
- Executive summary of security posture
- Analysis of the most critical findings
- Clear, actionable recommendations
- Compliance implications

## Customizing the Tool

### Modifying Finding Categories
Edit the collection functions in `src/lambda/index.py` to adjust detection criteria.

### Changing AI Analysis
Modify `src/lambda/bedrock_integration.py` to adjust the AI prompts or response handling.

### Adding New Services
To integrate additional AWS services:
1. Create a new collection function in `index.py`
2. Add the service to the Lambda handler
3. Update the IAM permissions in the CloudFormation template

## Code and Security Auditing

Before deploying to production, audit these critical components:

### Code Review
- **Lambda Handler (`index.py`)**: Check for potential credential leaks or debug logs
- **Bedrock Integration (`bedrock_integration.py`)**: Review AI prompt security and data handling
- **Error Handling**: Verify all external service calls have proper exception handling

### Security Review
- **IAM Permissions**: Review CloudFormation template to ensure least privilege
- **Data Handling**: Ensure sensitive findings are properly secured in S3 and emails
- **Log Management**: Check what's being logged to CloudWatch (should not include sensitive data)

### Compliance Documentation

For SOC 2 Type 2 and other compliance frameworks, document:

1. **Tool Implementation**: Document the tool's deployment as evidence of access review controls
2. **Regular Execution**: Keep evidence that reviews run monthly (CloudWatch logs)
3. **Issue Tracking**: Document your process for addressing findings
4. **Report Retention**: Define and document your retention policy for reports (typically minimum 1 year)
5. **Verification Process**: Document who reviews the reports and takes action on findings

## Testing Edge Cases and Error Handling

It's recommended to test these edge cases:

### Service Failures
- **Bedrock API failures**: The tool should fall back to raw findings without AI summaries
- **SES delivery issues**: Check logs for proper error handling and retries
- **S3 upload failures**: Ensure reports can still be delivered by email

### Configuration Scenarios
- **No Security Hub enabled**: Tool should provide helpful error message and partial results
- **No IAM Access Analyzer**: Tool should continue and note the missing data source
- **Minimal AWS account**: Test with a fresh AWS account to ensure good error messages

### Performance Testing
- Test with accounts of varying sizes to understand timing and resource requirements
- For large accounts (1000+ resources), monitor Lambda memory and timeout configuration