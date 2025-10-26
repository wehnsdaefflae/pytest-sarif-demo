"""SARIF v2.1.0 report generator for pytest results."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from .models import TestResult


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

    def generate(self, results: List[TestResult]) -> str:
        """Generate SARIF JSON from test results."""
        sarif = {
            "version": self.SARIF_VERSION,
            "$schema": self.SARIF_SCHEMA,
            "runs": [self._create_run(results)]
        }

        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def _create_run(self, results: List[TestResult]) -> Dict[str, Any]:
        """Create SARIF run object."""
        rules = self._generate_rules(results)
        sarif_results = self._generate_results(results)
        artifacts = self._generate_artifacts(results)

        return {
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

    def _generate_rules(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate SARIF rule definitions."""
        rules = {}

        for result in results:
            rule_id = self._get_rule_id(result)
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": result.test_name,
                    "shortDescription": {
                        "text": result.docstring or f"Security test: {result.test_name}"
                    },
                    "defaultConfiguration": {
                        "level": self._get_severity_level(result)
                    },
                    "properties": {
                        "tags": result.markers
                    }
                }

        return list(rules.values())

    def _generate_results(self, results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate SARIF result objects for failed tests."""
        sarif_results = []

        for result in results:
            if result.outcome == "failed":
                sarif_results.append({
                    "ruleId": self._get_rule_id(result),
                    "level": self._get_severity_level(result),
                    "message": {
                        "text": result.longrepr or "Test failed"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": result.file_path,
                                    "uriBaseId": "%SRCROOT%"
                                },
                                "region": {
                                    "startLine": result.line_number,
                                    "startColumn": 1
                                }
                            }
                        }
                    ],
                    "properties": {
                        "test_outcome": result.outcome,
                        "test_duration": result.duration,
                        "test_markers": result.markers
                    }
                })

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
