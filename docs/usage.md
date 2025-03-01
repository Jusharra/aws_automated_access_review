# AWS Access Review - Usage Guide

This document provides detailed instructions for using the AWS Access Review tool.

## Deployment

### Using the Deployment Script
The easiest way to deploy the tool is using the provided deployment script:

```bash
./scripts/deploy.sh
```

This script will:
1. Package the Lambda function
2. Deploy the CloudFormation stack
3. Configure the required permissions

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
It's recommended to set up a scheduled CloudWatch Event to trigger the Lambda regularly:

1. Navigate to Amazon EventBridge in the AWS Console
2. Create a new rule with a schedule expression (e.g., `rate(7 days)`)
3. Set the Lambda function as the target

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