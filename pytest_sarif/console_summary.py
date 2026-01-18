"""Console summary generator for CI/CD pipeline integration.

Provides clean, actionable terminal output suitable for CI/CD pipelines,
GitHub Actions, and automated security gates.
"""

from typing import List, Optional

from .models import TestResult
from .statistics import calculate_statistics, get_security_summary, get_test_severity
from .owasp_metadata import get_owasp_markers_from_test, get_owasp_category


# ANSI color codes for terminal output
class Colors:
    """ANSI escape codes for colored terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def generate_console_summary(
    results: List[TestResult],
    risk_score: Optional[any] = None,
    show_colors: bool = True,
    verbose: bool = False
) -> str:
    """Generate a CI/CD-friendly console summary.

    Args:
        results: List of test results
        risk_score: Optional risk score from RiskScoringEngine
        show_colors: Whether to include ANSI colors (disable for log files)
        verbose: Whether to show detailed failure information

    Returns:
        Formatted string for console output
    """
    stats = calculate_statistics(results)
    summary = get_security_summary(results)

    # Color helpers
    c = Colors if show_colors else type('NoColor', (), {k: '' for k in dir(Colors) if not k.startswith('_')})()

    lines = []

    # Header
    lines.append("")
    lines.append(f"{c.BOLD}{'='*60}{c.RESET}")
    lines.append(f"{c.BOLD}  LLM Security Test Results{c.RESET}")
    lines.append(f"{c.BOLD}{'='*60}{c.RESET}")
    lines.append("")

    # Quick status indicator
    if stats["failed"] == 0:
        status = f"{c.GREEN}{c.BOLD}PASSED{c.RESET}"
        status_icon = f"{c.GREEN}[OK]{c.RESET}"
    elif summary["critical_high_failures"] > 0:
        status = f"{c.RED}{c.BOLD}CRITICAL{c.RESET}"
        status_icon = f"{c.RED}[!!]{c.RESET}"
    else:
        status = f"{c.YELLOW}{c.BOLD}FAILED{c.RESET}"
        status_icon = f"{c.YELLOW}[!]{c.RESET}"

    lines.append(f"  {status_icon} Security Status: {status}")
    lines.append("")

    # Summary stats
    lines.append(f"  {c.CYAN}Test Summary:{c.RESET}")
    lines.append(f"    Total:   {stats['total']}")
    lines.append(f"    Passed:  {c.GREEN}{stats['passed']}{c.RESET}")
    lines.append(f"    Failed:  {c.RED if stats['failed'] > 0 else ''}{stats['failed']}{c.RESET}")
    lines.append(f"    Skipped: {stats['skipped']}")
    lines.append(f"    Rate:    {stats['pass_rate']:.1f}%")
    lines.append("")

    # Severity breakdown (only if there are failures)
    if stats["failed"] > 0:
        lines.append(f"  {c.CYAN}Severity Breakdown:{c.RESET}")
        severity_colors = {
            "critical": c.RED,
            "high": c.MAGENTA,
            "medium": c.YELLOW,
            "low": c.BLUE,
            "info": ""
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            failed_count = stats["by_severity"].get(sev, {}).get("failed", 0)
            if failed_count > 0:
                color = severity_colors[sev]
                lines.append(f"    {color}{sev.upper()}: {failed_count} failure(s){c.RESET}")
        lines.append("")

    # OWASP categories with failures
    failed_categories = [
        cat_id for cat_id, cat_stats in stats["owasp_categories"].items()
        if cat_stats["failed"] > 0
    ]
    if failed_categories:
        lines.append(f"  {c.CYAN}OWASP Categories Affected:{c.RESET}")
        for cat_id in sorted(failed_categories):
            cat_stats = stats["owasp_categories"][cat_id]
            category = get_owasp_category(f"owasp_{cat_id.lower()}")
            cat_name = category.name if category else cat_id
            lines.append(f"    {c.YELLOW}{cat_id}{c.RESET}: {cat_name} ({cat_stats['failed']} failures)")
        lines.append("")

    # Risk score (if available)
    if risk_score:
        risk_colors = {
            "critical": c.RED,
            "high": c.MAGENTA,
            "medium": c.YELLOW,
            "low": c.GREEN,
            "minimal": c.GREEN
        }
        risk_color = risk_colors.get(risk_score.risk_level, "")
        lines.append(f"  {c.CYAN}Risk Assessment:{c.RESET}")
        lines.append(f"    Score: {risk_color}{risk_score.overall_score:.0f}/100 ({risk_score.risk_level.upper()}){c.RESET}")
        lines.append(f"    Confidence: {risk_score.confidence*100:.0f}%")
        lines.append("")

    # Verbose mode: show failed test details
    if verbose and stats["failed"] > 0:
        failed_results = [r for r in results if r.outcome == "failed"]
        lines.append(f"  {c.CYAN}Failed Tests:{c.RESET}")
        for result in failed_results[:10]:  # Limit to first 10
            severity = get_test_severity(result)
            sev_color = severity_colors.get(severity, "")
            lines.append(f"    {sev_color}[{severity.upper()}]{c.RESET} {result.test_name}")
            lines.append(f"           {result.file_path}:{result.line_number}")
        if len(failed_results) > 10:
            lines.append(f"    ... and {len(failed_results) - 10} more")
        lines.append("")

    # Security posture assessment
    posture = summary["security_posture"]
    posture_messages = {
        "strong": f"{c.GREEN}Security posture is STRONG - all tests passing{c.RESET}",
        "critical": f"{c.RED}CRITICAL issues detected - immediate action required{c.RESET}",
        "needs_attention": f"{c.YELLOW}High severity issues detected - prioritize remediation{c.RESET}",
        "moderate": f"{c.YELLOW}Some issues detected but manageable{c.RESET}",
        "weak": f"{c.RED}Multiple security failures - comprehensive review needed{c.RESET}"
    }
    lines.append(f"  {posture_messages.get(posture, 'Unknown posture')}")
    lines.append("")

    # Footer with exit code hint
    lines.append(f"{c.BOLD}{'='*60}{c.RESET}")
    if stats["failed"] > 0:
        lines.append(f"  {c.RED}Exit code: 1 (failures detected){c.RESET}")
    else:
        lines.append(f"  {c.GREEN}Exit code: 0 (all tests passed){c.RESET}")
    lines.append("")

    return "\n".join(lines)


def print_console_summary(
    results: List[TestResult],
    risk_score: Optional[any] = None,
    verbose: bool = False
) -> None:
    """Print console summary directly to stdout.

    Args:
        results: List of test results
        risk_score: Optional risk score
        verbose: Whether to show detailed failure information
    """
    print(generate_console_summary(results, risk_score, show_colors=True, verbose=verbose))
