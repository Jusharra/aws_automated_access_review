import os
import subprocess
import unittest


class TestCodeStyle(unittest.TestCase):
    """Test cases for code style compliance."""

    def test_flake8_compliance(self):
        """Test that the code complies with flake8 standards."""
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        # Run flake8 on the source code
        result = subprocess.run(
            ["flake8", os.path.join(project_root, "src")],
            capture_output=True,
            text=True,
        )

        # Check if flake8 found any issues
        if result.returncode != 0:
            self.fail(f"flake8 found code style issues:\n{result.stdout}")


class TestBlackFormatting(unittest.TestCase):
    """Test cases for black formatting compliance."""

    def test_black_formatting(self):
        """Test that the code is formatted according to black standards."""
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        # Run black in check mode on the source code
        result = subprocess.run(
            ["black", "--check", os.path.join(project_root, "src")],
            capture_output=True,
            text=True,
        )

        # Check if black found any formatting issues
        if result.returncode != 0:
            self.fail(f"black found formatting issues:\n{result.stdout}")


class TestImportOrder(unittest.TestCase):
    """Test cases for import order compliance."""

    def test_isort_compliance(self):
        """Test that imports are sorted according to isort standards."""
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

        # Check if isort is installed
        try:
            # Run isort in check mode on the source code
            result = subprocess.run(
                ["isort", "--check", os.path.join(project_root, "src")],
                capture_output=True,
                text=True,
            )

            # Check if isort found any issues
            if result.returncode != 0:
                self.fail(f"isort found import order issues:\n{result.stdout}")
        except FileNotFoundError:
            # Skip the test if isort is not installed
            self.skipTest("isort is not installed")
