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

echo "Getting Lambda function name from CloudFormation stack..."
LAMBDA_FUNCTION=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" $AWS_CMD_PROFILE --query "Stacks[0].Outputs[?OutputKey=='AccessReviewLambdaArn'].OutputValue" --output text)

if [ -z "$LAMBDA_FUNCTION" ]; then
  echo "Error: Could not find Lambda function ARN in stack outputs."
  echo "Make sure the stack '$STACK_NAME' exists and has been deployed successfully."
  exit 1
fi

echo "Found Lambda function: $LAMBDA_FUNCTION"

echo "Invoking Lambda function to run an immediate access review report..."
aws lambda invoke \
  --function-name "$LAMBDA_FUNCTION" \
  --invocation-type Event \
  --payload '{}' \
  --region "$REGION" \
  $AWS_CMD_PROFILE \
  /dev/null

echo "Lambda function invoked successfully!"
echo "The access review report will be generated and sent to your email shortly."
echo "This process may take a few minutes to complete."
echo ""
echo "You can check the Lambda function logs in CloudWatch for progress:"
echo "https://$REGION.console.aws.amazon.com/cloudwatch/home?region=$REGION#logsV2:log-groups/log-group/aws/lambda/$(basename $LAMBDA_FUNCTION)" 