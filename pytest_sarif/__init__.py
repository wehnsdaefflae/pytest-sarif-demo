"""pytest-sarif-demo: Pytest plugin for generating SARIF security reports."""

__version__ = "0.1.0"

from .console_summary import generate_console_summary, print_console_summary

__all__ = [
    "generate_console_summary",
    "print_console_summary",
]
