# Email Setup Guide for AWS SES

This guide will walk you through setting up Amazon Simple Email Service (SES) for receiving access review reports - a crucial step for adding this tool to your GRC portfolio.

## Why This Matters For Your Portfolio

Configuring AWS SES properly demonstrates:
- Your understanding of AWS service configuration
- Security best practices for email communication
- Ability to set up automated notification systems

## Steps to Verify Your Email Address

### Step 1: Navigate to the SES Console

1. Log in to your AWS account
2. Go to the SES Console: https://console.aws.amazon.com/ses/
3. Select the region you'll deploy the access review tool in
   - For best results with Amazon Bedrock integration, use `us-east-1` or `us-west-2`

### Step 2: Verify Your Email Address

1. In the SES console, select **Verified identities** from the left menu
2. Click **Create identity**
3. Select **Email address** as the identity type
4. Enter your email address where you want to receive access review reports
5. Leave default settings and click **Create identity**

### Step 3: Complete Verification

1. AWS will send a verification email to the address you provided
2. Check your inbox (and spam/junk folders if needed)
3. Open the verification email from AWS
4. Click the verification link in the email

### Step 4: Confirm Verification Status

1. Return to the SES console
2. Your email should now show a **Verified** status
3. You're now ready to receive access review reports!

## Troubleshooting

- **No verification email received?** Check your spam folder, or try a different email address
- **Verification link expired?** Return to the SES console and request a new verification email
- **Still having issues?** Ensure you're in the same region where you're deploying the access review tool

## Next Steps

Once your email is verified, return to the main deployment guide to complete setting up the AWS Automated Access Review tool. This verified email will be used to receive security reports that you can showcase in your GRC portfolio.

Remember: Email verification is a SES requirement, not just for this tool. This demonstrates AWS's commitment to prevent email abuse, an important compliance and security concept.