#!/bin/bash

# Exit on error
set -e

# Colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Setting up development environment for AWS Access Review tool...${NC}"

# Check if python3 is installed
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
    exit 1
fi

# Check Python version
echo -e "Checking Python version..."
python_version=$(python3 --version)
echo -e "Using ${YELLOW}$python_version${NC}"

# Check if virtualenv is installed
if ! python3 -m venv --help &>/dev/null; then
    echo -e "${YELLOW}Installing virtualenv...${NC}"
    pip3 install virtualenv
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}Virtual environment created.${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install or upgrade pip
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt

# Create local AWS credentials for testing if they don't exist
if [ ! -f ~/.aws/credentials ]; then
    echo -e "${YELLOW}Setting up mock AWS credentials for local testing...${NC}"
    mkdir -p ~/.aws
    echo "[default]" > ~/.aws/credentials
    echo "aws_access_key_id = testing" >> ~/.aws/credentials
    echo "aws_secret_access_key = testing" >> ~/.aws/credentials
    echo "aws_session_token = testing" >> ~/.aws/credentials
    echo -e "${GREEN}Mock AWS credentials created.${NC}"
fi

# Create local AWS config if it doesn't exist
if [ ! -f ~/.aws/config ]; then
    echo -e "${YELLOW}Setting up mock AWS config for local testing...${NC}"
    mkdir -p ~/.aws
    echo "[default]" > ~/.aws/config
    echo "region = us-east-1" >> ~/.aws/config
    echo -e "${GREEN}Mock AWS config created.${NC}"
fi

# Run a basic test to verify setup, but handle potential failures gracefully
echo -e "${YELLOW}Running basic test to verify setup...${NC}"
if python -m pytest tests/unit/test_handler.py::TestHandler::test_lambda_handler -v; then
    echo -e "${GREEN}Basic test passed!${NC}"
else
    echo -e "${RED}Basic test failed, but continuing with setup.${NC}"
    echo -e "${YELLOW}You may need to fix some issues before running a full test suite.${NC}"
fi

echo -e "${GREEN}Development environment setup complete!${NC}"
echo -e "To activate the environment, run: ${YELLOW}source venv/bin/activate${NC}"
echo -e "To run all tests, run: ${YELLOW}./run_tests.sh${NC}"
echo -e "To lint code, run: ${YELLOW}black src/ tests/ && flake8 src/ tests/${NC}"
echo -e "To run the AWS access report, run: ${YELLOW}./run_report.sh${NC}"