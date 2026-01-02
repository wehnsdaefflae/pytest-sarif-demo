# Security Policy Framework

This pytest-sarif plugin now includes a comprehensive security policy framework that enables organizations to define, enforce, and monitor compliance with their security requirements.

## Features

### 1. Risk-Based Scoring
- **Comprehensive Risk Assessment**: Automatically calculates risk scores (0-100) based on:
  - Test failure rates and severity distribution
  - OWASP category-specific risks with impact multipliers
  - Historical trends and regression analysis
  - Policy compliance status
- **Risk Levels**: Critical, High, Medium, Low, Minimal
- **Confidence Scoring**: Provides confidence levels based on data availability
- **Actionable Recommendations**: Generates prioritized remediation guidance

### 2. Security Policy Configuration
Define organizational security requirements with:
- **Category-specific policies**: Set failure thresholds per OWASP category
- **Severity-based limits**: Control critical, high, medium severity failures
- **Trend requirements**: Enforce continuous improvement
- **Regression policies**: Prevent security backsliding
- **Compliance frameworks**: Map to HIPAA, PCI-DSS, SOC2, ISO 27001, etc.

### 3. Pre-built Policy Templates
Ready-to-use policies for different industries:
- **Healthcare (HIPAA)**: `policies/healthcare-hipaa.json`
- **Financial (PCI-DSS)**: `policies/financial-pci-dss.json`
- **Enterprise Strict**: `policies/enterprise-strict.json`
- **Startup Balanced**: `policies/startup-balanced.json`

## Usage

### Basic Usage

```bash
# Run with default policy (balanced)
pytest tests/ -v --sarif-output=results/pytest-results.sarif --enable-policy

# Use industry-specific policy
pytest tests/ -v --sarif-output=results/pytest-results.sarif \
  --security-policy=policies/healthcare-hipaa.json \
  --enable-policy

# Generate full reports with policy compliance
pytest tests/ -v \
  --sarif-output=results/pytest-results.sarif \
  --report-formats=html,json,markdown \
  --security-policy=policies/financial-pci-dss.json \
  --enable-policy
```

### Policy Enforcement

When `--enable-policy` is set:
- Policy violations are displayed in test summary
- Risk scores are calculated and shown
- Build fails if violations exceed policy thresholds (unless `warning_only: true`)
- All reports include policy compliance sections

### Creating Custom Policies

Create a JSON policy file based on the template:

```json
{
  "name": "my-custom-policy",
  "description": "Custom security policy for my organization",
  "version": "1.0.0",
  "max_critical_failures": 0,
  "max_high_failures": 2,
  "max_medium_failures": 5,
  "max_total_failures": 10,
  "max_risk_score": 65.0,
  "allow_regressions": false,
  "compliance_frameworks": ["Custom Framework"],
  "category_policies": {
    "owasp_llm01": {
      "category": "owasp_llm01",
      "priority": "critical",
      "max_failures": 0,
      "required": true,
      "enforcement_level": "strict"
    }
  }
}
```

## Risk Scoring

The risk scoring engine evaluates:

1. **Failure Rate Risk** (25%): Exponential penalty for high failure rates
2. **Severity Impact** (25%): Weighted by critical/high/medium/low severity
3. **Category Risk** (20%): OWASP-specific multipliers (e.g., Prompt Injection × 1.5)
4. **Trend Risk** (15%): Degrading trends and flaky tests
5. **Regression Risk** (10%): New failures vs baseline
6. **Policy Compliance** (5%): Violations of organizational policies

### Risk Level Thresholds
- **Critical**: 80-100 (Do not deploy)
- **High**: 60-79 (Significant issues, prioritize remediation)
- **Medium**: 40-59 (Moderate risk, plan fixes)
- **Low**: 20-39 (Minor issues)
- **Minimal**: 0-19 (Acceptable risk)

## Reports

All report formats (HTML, JSON, Markdown) include:
- **Risk Assessment**: Overall risk score, factors, and recommendations
- **Policy Compliance**: Status, violations, and compliance frameworks
- **Violation Details**: Severity breakdown, current vs threshold values
- **Remediation Guidance**: Context-specific recommendations

### Example HTML Report Sections
- Risk Assessment dashboard with visual risk indicators
- Policy Compliance status with violation breakdown
- Critical violations with remediation steps
- Risk factor charts showing contribution to overall risk

### Example JSON Report
```json
{
  "risk_assessment": {
    "overall_score": 45.2,
    "risk_level": "medium",
    "confidence": 0.85,
    "recommendations": [...]
  },
  "policy_compliance": {
    "policy_name": "healthcare-hipaa",
    "is_compliant": false,
    "total_violations": 3,
    "violations": [...]
  }
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
- name: Run Security Tests with Policy Enforcement
  run: |
    pytest tests/ -v \
      --sarif-output=results/pytest-results.sarif \
      --report-formats=html,json \
      --security-policy=policies/enterprise-strict.json \
      --enable-policy \
      --compare-baseline

- name: Upload Reports
  uses: actions/upload-artifact@v3
  with:
    name: security-reports
    path: results/
```

### Exit Codes
- `0`: All tests passed and policy compliant
- `1`: Test failures or policy violations (when `fail_on_policy_violation: true`)

## Policy Configuration Reference

### Global Thresholds
- `max_critical_failures`: Maximum allowed critical severity failures
- `max_high_failures`: Maximum allowed high severity failures
- `max_medium_failures`: Maximum allowed medium severity failures
- `max_total_failures`: Maximum total failures across all severities
- `max_risk_score`: Maximum acceptable risk score (0-100)

### Trend Requirements
- `require_trend_improvement`: Fail if security posture is degrading
- `allow_regressions`: Whether to allow tests that previously passed to fail
- `max_flaky_tests`: Maximum number of flaky tests tolerated

### Category Policies
- `priority`: Importance level (critical/high/medium/low)
- `max_failures`: Maximum failures allowed for this category
- `required`: Whether testing this category is mandatory
- `enforcement_level`: strict/moderate/lenient

## Benefits

1. **Measurable Security**: Quantify security posture with risk scores
2. **Compliance Automation**: Automated enforcement of security policies
3. **Risk Prioritization**: Focus on highest-impact vulnerabilities
4. **Trend Monitoring**: Track security improvements over time
5. **Industry Standards**: Pre-configured for HIPAA, PCI-DSS, etc.
6. **CI/CD Ready**: Automated policy enforcement in pipelines
7. **Grant-Ready**: Demonstrates mature security practices for funding applications
