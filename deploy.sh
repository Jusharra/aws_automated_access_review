#!/bin/bash
set -e

# Configuration
STACK_NAME="aws-access-review"
REGION="us-east-1"  # Change to your preferred region
RECIPIENT_EMAIL=""  # Set this to your email address
SCHEDULE="rate(7 days)"  # Default: weekly
AWS_PROFILE=""  # AWS profile to use

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --stack-name)
      STACK_NAME="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --email)
      RECIPIENT_EMAIL="$2"
      shift 2
      ;;
    --schedule)
      SCHEDULE="$2"
      shift 2
      ;;
    --profile)
      AWS_PROFILE="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# Validate email
if [ -z "$RECIPIENT_EMAIL" ]; then
  echo "Error: Recipient email is required. Use --email to specify."
  exit 1
fi

# Set AWS profile if specified
AWS_CMD_PROFILE=""
if [ -n "$AWS_PROFILE" ]; then
  AWS_CMD_PROFILE="--profile $AWS_PROFILE"
  echo "Using AWS profile: $AWS_PROFILE"
fi

# Create a unique S3 bucket for Lambda code
CODE_BUCKET="${STACK_NAME}-lambda-code-$(date +%s)"
echo "Creating S3 bucket for Lambda code: $CODE_BUCKET"
aws s3 mb "s3://$CODE_BUCKET" --region "$REGION" $AWS_CMD_PROFILE

# Upload Lambda code to S3
echo "Uploading Lambda code to S3..."
aws s3 cp lambda_function.zip "s3://$CODE_BUCKET/" --region "$REGION" $AWS_CMD_PROFILE

# Deploy CloudFormation stack
echo "Deploying CloudFormation stack: $STACK_NAME"
aws cloudformation deploy \
  --template-file templates/access-review-real.yaml \
  --stack-name "$STACK_NAME" \
  --capabilities CAPABILITY_IAM \
  --region "$REGION" \
  $AWS_CMD_PROFILE \
  --parameter-overrides \
    RecipientEmail="$RECIPIENT_EMAIL" \
    ScheduleExpression="$SCHEDULE" \
    LambdaCodeBucket="$CODE_BUCKET" \
    LambdaCodeKey="lambda_function.zip"

# Output stack information
echo "Stack deployment initiated. Waiting for completion..."
aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE || \
aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE

echo "Deployment completed successfully!"
echo "Stack outputs:"
aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE --query "Stacks[0].Outputs" --output table

echo ""
echo "IMPORTANT: Verify your email address to receive reports"
echo "An email verification message has been sent to $RECIPIENT_EMAIL"
echo "You must click the verification link in that email to receive access review reports"