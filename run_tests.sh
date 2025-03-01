#!/bin/bash
set -e

# Display help information
if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
  echo "Usage: ./run_tests.sh [options]"
  echo ""
  echo "Options:"
  echo "  -h, --help     Show this help message"
  echo "  -u, --unit     Run only unit tests"
  echo "  -c, --cfn      Run only CloudFormation template tests"
  echo "  -s, --style    Run only code style checks"
  echo "  -v, --verbose  Run tests with verbose output"
  echo "  --coverage     Run tests with coverage report"
  echo "  --fix          Fix code style issues where possible (with black)"
  exit 0
fi

# Parse arguments
RUN_UNIT=true
RUN_CFN=true
RUN_STYLE=true
VERBOSE=""
COVERAGE=""
FIX_STYLE=false

for arg in "$@"
do
  case $arg in
    -u|--unit)
    RUN_UNIT=true
    RUN_CFN=false
    RUN_STYLE=false
    shift
    ;;
    -c|--cfn)
    RUN_UNIT=false
    RUN_CFN=true
    RUN_STYLE=false
    shift
    ;;
    -s|--style)
    RUN_UNIT=false
    RUN_CFN=false
    RUN_STYLE=true
    shift
    ;;
    -v|--verbose)
    VERBOSE="-v"
    shift
    ;;
    --coverage)
    COVERAGE="--cov=src"
    shift
    ;;
    --fix)
    FIX_STYLE=true
    shift
    ;;
  esac
done

# Check if Python and required packages are installed
if ! command -v python3 &> /dev/null; then
  echo "Python 3 is required but not installed. Please install Python 3 and try again."
  exit 1
fi

if ! command -v pip3 &> /dev/null; then
  echo "pip3 is required but not installed. Please install pip3 and try again."
  exit 1
fi

# Install required packages if not already installed
echo "Checking for required packages..."
pip3 install -q -r requirements.txt

# Run code style checks if requested
if [ "$RUN_STYLE" = true ]; then
  echo "Running code style checks..."
  
  # Run black in check mode (or fix mode if --fix was specified)
  if [ "$FIX_STYLE" = true ]; then
    echo "Formatting Python code with black..."
    python3 -m black src/ tests/
  else
    echo "Checking Python code formatting with black..."
    python3 -m black --check src/ tests/
  fi
  
  # Run flake8 for linting
  echo "Linting Python code with flake8..."
  python3 -m flake8 src/ tests/
  
  # Run cfn-lint on CloudFormation templates
  echo "Linting CloudFormation templates with cfn-lint..."
  python3 -m cfnlint templates/*.yaml
fi

# Run unit tests if requested
if [ "$RUN_UNIT" = true ]; then
  echo "Running unit tests..."
  if [ -n "$COVERAGE" ]; then
    python3 -m pytest tests/unit $VERBOSE $COVERAGE
  else
    python3 -m pytest tests/unit $VERBOSE
  fi
fi

# Run CloudFormation template tests if requested
if [ "$RUN_CFN" = true ]; then
  echo "Running CloudFormation template tests..."
  python3 -m pytest tests/cfn $VERBOSE
fi

# If coverage was requested, display the report
if [ -n "$COVERAGE" ]; then
  echo "Generating coverage report..."
  python3 -m coverage report -m
fi

echo "All tests completed successfully!" 