#!/bin/bash
set -e

# Configuration
STACK_NAME="aws-access-review"
REGION="us-east-1"  # Change to your preferred region
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

# Set AWS profile if specified
AWS_CMD_PROFILE=""
if [ -n "$AWS_PROFILE" ]; then
  AWS_CMD_PROFILE="--profile $AWS_PROFILE"
  echo "Using AWS profile: $AWS_PROFILE"
fi

# Confirm deletion
echo "This will delete the CloudFormation stack '$STACK_NAME' and all associated resources."
echo "This action cannot be undone."
read -p "Are you sure you want to proceed? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Cleanup cancelled."
  exit 0
fi

# Get S3 bucket names from the stack
echo "Getting S3 bucket names from the stack..."
REPORT_BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE --query "Stacks[0].Outputs[?OutputKey=='ReportBucketName'].OutputValue" --output text)

# Get Lambda code bucket from the stack parameters
CODE_BUCKET=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE --query "Stacks[0].Parameters[?ParameterKey=='LambdaCodeBucket'].ParameterValue" --output text)

# Delete the CloudFormation stack
echo "Deleting CloudFormation stack: $STACK_NAME"
aws cloudformation delete-stack --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE

echo "Waiting for stack deletion to complete..."
aws cloudformation wait stack-delete-complete --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE

# Empty and delete S3 buckets
if [ -n "$REPORT_BUCKET" ]; then
  echo "Emptying and deleting report bucket: $REPORT_BUCKET"
  aws s3 rm "s3://$REPORT_BUCKET" --recursive --region "$REGION" $AWS_CMD_PROFILE
  aws s3 rb "s3://$REPORT_BUCKET" --region "$REGION" $AWS_CMD_PROFILE
fi

if [ -n "$CODE_BUCKET" ]; then
  echo "Emptying and deleting Lambda code bucket: $CODE_BUCKET"
  aws s3 rm "s3://$CODE_BUCKET" --recursive --region "$REGION" $AWS_CMD_PROFILE
  aws s3 rb "s3://$CODE_BUCKET" --region "$REGION" $AWS_CMD_PROFILE
fi

echo "Cleanup completed successfully!" 