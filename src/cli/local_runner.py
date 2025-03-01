#!/usr/bin/env python3
"""
CLI tool to run AWS Access Review locally.
This module provides a convenient way to test the Lambda function without deploying to AWS.
"""

import os
import sys
import json
import argparse

# Add the Lambda directory to the path so we can import the functions
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../lambda"))
)

try:
    import index
except ImportError:
    print("Error: Cannot import Lambda handler. Make sure the Lambda code exists.")
    sys.exit(1)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run AWS Access Review locally")
    parser.add_argument("--email", "-e", help="Email to send report to")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument(
        "--force-real",
        "-f",
        action="store_true",
        help="Force real execution with SES email delivery",
    )
    return parser.parse_args()


def setup_environment():
    """Set up environment variables for local execution."""
    os.environ.setdefault("REPORT_BUCKET", "local-test-bucket")
    os.environ.setdefault("RECIPIENT_EMAIL", "test@example.com")


def main():
    """Main entry point for the CLI."""
    args = parse_args()
    setup_environment()

    # Override environment variables with command line args
    if args.email:
        os.environ["RECIPIENT_EMAIL"] = args.email

    # Prepare event for Lambda function
    event = {}
    if args.force_real:
        event["force_real_execution"] = True
    if args.email:
        event["recipient_email"] = args.email

    print(f"Running AWS Access Review locally with event: {json.dumps(event)}")

    # Run Lambda function
    try:
        result = index.handler(event, {})
        print(f"Lambda execution complete with status: {result['statusCode']}")

        # Write result to file if specified
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
            print(f"Results written to {args.output}")
        else:
            print(f"Response: {json.dumps(result, indent=2)}")

        return 0
    except Exception as e:
        print(f"Error executing Lambda function: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
