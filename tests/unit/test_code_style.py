import os
import pytest
import subprocess
from pathlib import Path

def get_project_root():
    """Return the path to the project root directory."""
    return Path(__file__).parent.parent.parent

def test_flake8_compliance():
    """Test that Python code complies with flake8 standards."""
    project_root = get_project_root()
    src_dir = project_root / "src"
    tests_dir = project_root / "tests"
    
    # Run flake8 on src and tests directories
    cmd = ["flake8", str(src_dir), str(tests_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # If flake8 found issues, the output will contain the details
    if result.returncode != 0:
        # Print the output for debugging
        print(f"flake8 output:\n{result.stdout}")
        assert False, f"flake8 found code style issues:\n{result.stdout}"
    
    # If we got here, flake8 passed

def test_black_compliance():
    """Test that Python code complies with black formatting standards."""
    project_root = get_project_root()
    src_dir = project_root / "src"
    tests_dir = project_root / "tests"
    
    # Run black in check mode on src and tests directories
    cmd = ["black", "--check", str(src_dir), str(tests_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # If black found issues, the output will contain the details
    if result.returncode != 0:
        # Print the output for debugging
        print(f"black output:\n{result.stderr}")
        assert False, f"black found code formatting issues:\n{result.stderr}"
    
    # If we got here, black passed

def test_python_syntax():
    """Test that all Python files have valid syntax."""
    project_root = get_project_root()
    
    # Find all Python files in the project
    python_files = []
    for root, _, files in os.walk(project_root):
        # Skip virtual environment directories
        if "venv" in root or ".venv" in root or "__pycache__" in root:
            continue
        
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))
    
    # Check each file for syntax errors
    for file_path in python_files:
        cmd = ["python", "-m", "py_compile", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        assert result.returncode == 0, f"Syntax error in {file_path}:\n{result.stderr}"
    
    # If we got here, all files have valid syntax 