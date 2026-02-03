"""CLI entry point for pytest-sarif-demo.

Provides quick access to security test execution and report generation.

Usage:
    python -m pytest_sarif [options] [test_path]

Examples:
    python -m pytest_sarif                    # Run all tests
    python -m pytest_sarif tests/ -v          # Run with verbose output
    python -m pytest_sarif --check            # Validate test suite coverage
"""

import sys
import subprocess
from pathlib import Path

from .owasp_metadata import OWASP_LLM_CATEGORIES
from .statistics import get_coverage_gaps


def print_banner():
    """Print tool banner."""
    print("=" * 60)
    print("pytest-sarif-demo - LLM Security Testing Framework")
    print("OWASP Top 10 for LLM Applications")
    print("=" * 60)


def check_coverage():
    """Check OWASP category coverage without running tests."""
    print_banner()
    print("\nOWASP LLM Top 10 Categories:")
    print("-" * 60)
    for marker, category in sorted(OWASP_LLM_CATEGORIES.items()):
        print(f"  {category.id}: {category.name}")
    print("-" * 60)
    print(f"\nTotal categories: {len(OWASP_LLM_CATEGORIES)}")
    print("\nRun tests with: python -m pytest_sarif tests/")


def run_tests(args: list):
    """Run pytest with SARIF output configured."""
    # Ensure results directory exists
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest",
        "--sarif-output=results/pytest-results.sarif",
    ]
    cmd.extend(args)

    print_banner()
    print(f"\nRunning: {' '.join(cmd)}\n")

    return subprocess.call(cmd)


def main():
    """Main entry point."""
    args = sys.argv[1:]

    if "--check" in args:
        check_coverage()
        return 0

    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0

    # Default to tests/ if no path specified
    if not args or all(a.startswith("-") for a in args):
        args = ["tests/"] + args

    return run_tests(args)


if __name__ == "__main__":
    sys.exit(main())
