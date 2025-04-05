#!/bin/bash
set -e

# Configuration
STACK_NAME="aws-access-review"
REGION="us-east-1"  # Default region
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

# Verify AWS credentials are valid
echo "Verifying AWS credentials..."
if ! aws sts get-caller-identity $AWS_CMD_PROFILE --region "$REGION" &>/dev/null; then
  echo "Error: Unable to validate AWS credentials. Check your AWS configuration or profile."
  exit 1
fi
echo "AWS credentials verified."

# Get Lambda function name from CloudFormation stack
echo "Getting Lambda function ARN from CloudFormation stack..."
LAMBDA_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE --query "Stacks[0].Outputs[?OutputKey=='AccessReviewLambdaArn'].OutputValue" --output text)

if [ -z "$LAMBDA_ARN" ]; then
  echo "Error: Could not retrieve Lambda function ARN from stack outputs."
  exit 1
fi

echo "Found Lambda function: $LAMBDA_ARN"

# Invoke Lambda function
echo "Invoking Lambda function to generate access review report..."
aws lambda invoke \
  --function-name "$LAMBDA_ARN" \
  --invocation-type Event \
  --region "$REGION" \
  $AWS_CMD_PROFILE \
  /dev/null

echo "Lambda function invoked successfully!"
echo "The access review report will be generated and sent to the configured email address."
echo "This process may take several minutes to complete depending on the size of your AWS environment."
echo ""
echo "You can check the Lambda function logs in CloudWatch for progress:"
echo "https://$REGION.console.aws.amazon.com/cloudwatch/home?region=$REGION#logsV2:log-groups/log-group/aws/lambda/$(basename $LAMBDA_ARN)" 