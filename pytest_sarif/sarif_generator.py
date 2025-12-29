"""SARIF v2.1.0 report generator for pytest results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from .models import TestResult
from .owasp_metadata import (
    get_owasp_category,
    get_owasp_markers_from_test,
    get_cwe_tags,
    get_security_tags,
)


class SARIFGenerator:
    """Generates SARIF v2.1.0 compliant reports."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    SEVERITY_MAP = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "none"
    }

    def __init__(self, tool_name: str, tool_version: str, source_root: Path):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.source_root = source_root

    def generate(self, results: List[TestResult], baseline_analysis=None) -> str:
        """Generate SARIF JSON from test results.

        Args:
            results: List of test results
            baseline_analysis: Optional baseline regression analysis

        Returns:
            SARIF JSON string
        """
        sarif = {
            "version": self.SARIF_VERSION,
            "$schema": self.SARIF_SCHEMA,
            "runs": [self._create_run(results, baseline_analysis)]
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _create_run(self, results: List[TestResult], baseline_analysis=None) -> Dict[str, Any]:
        """Create SARIF run object."""
        rules = self._generate_rules(results)
        sarif_results = self._generate_results(results, baseline_analysis)
        artifacts = self._generate_artifacts(results)

        run = {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/wehnsdaefflac/pytest-sarif-demo",
                    "rules": rules
                }
            },
            "results": sarif_results,
            "artifacts": artifacts,
            "columnKind": "utf16CodeUnits",
            "invocations": [
                {
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).isoformat()
                }
            ]
        }

        # Add baseline comparison properties if available
        if baseline_analysis:
            run["properties"] = {
                "baseline_comparison": {
                    "has_regressions": baseline_analysis.has_regressions,
                    "has_improvements": baseline_analysis.has_improvements,
                    "regression_count": baseline_analysis.regression_count,
                    "improvement_count": baseline_analysis.improvement_count,
                    "regressed_tests": baseline_analysis.regressed_tests,
                    "fixed_tests": baseline_analysis.fixed_tests,
                    "baseline_pass_rate": baseline_analysis.baseline_pass_rate,
                    "current_pass_rate": baseline_analysis.current_pass_rate,
                    "pass_rate_change": baseline_analysis.pass_rate_change,
                    "severity_impact": baseline_analysis.severity_impact,
                    "owasp_impact": baseline_analysis.owasp_impact,
                    "regression_severity": baseline_analysis.regression_severity
                }
            }

        return run

    def _generate_rules(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions with OWASP metadata."""
        rules = {}

        for result in results:
            rule_id = self._get_rule_id(result)
            if rule_id not in rules:
                # Get OWASP category information
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = (
                    get_owasp_category(owasp_markers[0]) if owasp_markers else None
                )

                # Build rule definition
                rule = {
                    "id": rule_id,
                    "name": result.test_name,
                    "shortDescription": {
                        "text": result.docstring or f"Security test: {result.test_name}"
                    },
                    "defaultConfiguration": {"level": self._get_severity_level(result)},
                }

                # Add full description if OWASP category is available
                if owasp_category:
                    rule["fullDescription"] = {
                        "text": f"{owasp_category.name}: {owasp_category.full_description}"
                    }
                    rule["help"] = {
                        "text": owasp_category.help_text,
                        "markdown": f"# {owasp_category.name}\n\n{owasp_category.help_text}",
                    }

                # Build comprehensive property tags
                properties = {
                    "tags": result.markers + get_security_tags(result.markers),
                    "security-severity": self._get_numeric_severity(result),
                }

                # Add OWASP-specific properties
                if owasp_category:
                    properties["owasp-category"] = owasp_category.id
                    properties["owasp-name"] = owasp_category.name

                # Add CWE tags
                cwe_ids = get_cwe_tags(result.markers)
                if cwe_ids:
                    properties["cwe"] = cwe_ids

                rule["properties"] = properties

                # Add help URI if OWASP category has references
                if owasp_category and owasp_category.references:
                    rule["helpUri"] = owasp_category.references[0]

                rules[rule_id] = rule

        return list(rules.values())

    def _generate_results(self, results: List[TestResult], baseline_analysis=None) -> List[Dict[str, Any]]:
        """Generate SARIF result objects for failed tests."""
        sarif_results = []

        # Create set of regressed test IDs for quick lookup
        regressed_test_ids = set(baseline_analysis.regressed_tests) if baseline_analysis else set()

        for result in results:
            if result.outcome == "failed":
                # Get OWASP category for enriched messaging
                owasp_markers = get_owasp_markers_from_test(result.markers)
                owasp_category = (
                    get_owasp_category(owasp_markers[0]) if owasp_markers else None
                )

                message_text = result.longrepr or "Test failed"

                # Mark regressions prominently
                is_regression = result.nodeid in regressed_test_ids
                if is_regression:
                    message_text = f"⚠ REGRESSION: {message_text}"
                elif owasp_category:
                    message_text = f"[{owasp_category.id}] {message_text}"

                sarif_result = {
                    "ruleId": self._get_rule_id(result),
                    "level": self._get_severity_level(result),
                    "message": {"text": message_text},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result.file_path,
                                    "uriBaseId": "%SRCROOT%",
                                },
                                "region": {
                                    "startLine": result.line_number,
                                    "startColumn": 1,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "test_outcome": result.outcome,
                        "test_duration": result.duration,
                        "test_markers": result.markers,
                    },
                }

                # Mark as baseline regression
                if is_regression:
                    sarif_result["properties"]["baseline_regression"] = True
                    sarif_result["baselineState"] = "new"  # SARIF standard property for new issues

                # Add OWASP category to properties
                if owasp_category:
                    sarif_result["properties"]["owasp_category"] = owasp_category.id
                    sarif_result["properties"]["owasp_name"] = owasp_category.name

                    # Add remediation suggestions as SARIF fixes
                    if owasp_category.remediation_steps:
                        sarif_result["fixes"] = self._generate_fixes(owasp_category)

                # Add CWE information
                cwe_ids = get_cwe_tags(result.markers)
                if cwe_ids:
                    sarif_result["properties"]["cwe_ids"] = cwe_ids

                sarif_results.append(sarif_result)

        return sarif_results

    def _generate_artifacts(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate SARIF artifact objects."""
        artifacts = {}

        for result in results:
            if result.file_path not in artifacts:
                artifacts[result.file_path] = {
                    "location": {
                        "uri": result.file_path,
                        "uriBaseId": "%SRCROOT%"
                    }
                }

        return list(artifacts.values())

    def _get_rule_id(self, result: TestResult) -> str:
        """Generate unique rule ID from test."""
        # Remove parametrization brackets for cleaner rule IDs
        return result.test_name.replace("[", "_").replace("]", "")

    def _get_severity_level(self, result: TestResult) -> str:
        """Extract severity level from test markers."""
        for marker in result.markers:
            if marker in self.SEVERITY_MAP:
                return self.SEVERITY_MAP[marker]

        return "warning"  # Default severity

    def _get_numeric_severity(self, result: TestResult) -> str:
        """Get numeric severity score for security tools."""
        severity_scores = {
            "critical": "9.0",
            "high": "7.0",
            "medium": "5.0",
            "low": "3.0",
            "info": "0.0",
        }

        for marker in result.markers:
            if marker in severity_scores:
                return severity_scores[marker]

        return "5.0"  # Default medium severity

    def _generate_fixes(self, owasp_category) -> List[Dict[str, Any]]:
        """Generate SARIF fix objects from remediation steps.

        Args:
            owasp_category: OWASPCategory with remediation steps

        Returns:
            List of SARIF fix objects
        """
        fixes = []

        for idx, step in enumerate(owasp_category.remediation_steps, 1):
            fix = {
                "description": {
                    "text": f"Remediation step {idx}: {step}"
                },
                "artifactChanges": []  # Conceptual fixes, no specific file changes
            }
            fixes.append(fix)

        return fixes
