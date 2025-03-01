#!/usr/bin/env python3
"""
Test script to invoke the AWS Access Review Lambda function locally.
This script simulates the Lambda environment and invokes the handler function.
"""

import os
import sys
import json
import argparse
import boto3
from datetime import datetime


def main():
    """
    Main function to test the Lambda handler locally.
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Test AWS Access Review Lambda function locally"
    )
    parser.add_argument("--email", help="Recipient email address")
    parser.add_argument("--bucket", help="S3 bucket name for reports (optional)")
    parser.add_argument("--profile", help="AWS profile to use for credentials")
    args = parser.parse_args()

    # Set AWS profile if specified
    if args.profile:
        print(f"Using AWS profile: {args.profile}")
        boto3.setup_default_session(profile_name=args.profile)
        os.environ["AWS_PROFILE"] = args.profile

    print("Testing AWS Access Review Lambda function locally...")

    # Set required environment variables
    recipient_email = args.email if args.email else input("Enter recipient email: ")
    report_bucket = (
        args.bucket
        if args.bucket
        else input(
            "Enter S3 bucket name for reports (or leave empty to skip S3 upload): "
        )
    )

    os.environ["RECIPIENT_EMAIL"] = recipient_email
    if report_bucket:
        os.environ["REPORT_BUCKET"] = report_bucket

    # Add the deployment directory to the Python path
    sys.path.append("deployment")

    # Import the Lambda handler
    try:
        from index import handler
    except ImportError:
        print(
            "Error: Could not import the Lambda handler. "
            "Make sure the deployment directory contains index.py"
        )
        sys.exit(1)

    # Create a test event (empty event as the Lambda doesn't use the event)
    test_event = {}

    # Create a test context
    class TestContext:
        function_name = "local-test-access-review"
        memory_limit_in_mb = 512
        invoked_function_arn = (
            "arn:aws:lambda:us-east-1:123456789012:function:local-test"
        )
        aws_request_id = f"local-test-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        log_group_name = "/aws/lambda/local-test"
        log_stream_name = f"local-test-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        def get_remaining_time_in_millis(self):
            return 300000  # 5 minutes

    test_context = TestContext()

    # Invoke the handler
    print("\nInvoking Lambda handler...")
    try:
        response = handler(test_event, test_context)
        print("\nLambda execution completed successfully!")
        print(f"Response: {json.dumps(response, indent=2)}")
    except Exception as e:
        print(f"\nError executing Lambda: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
