"""Compliance framework mapping for OWASP LLM vulnerabilities.

Maps OWASP Top 10 for LLM Applications to major security and AI governance frameworks
including NIST AI RMF, ISO/IEC 42001, EU AI Act, NIST CSF 2.0, SOC 2, and ISO 27001.
"""

from typing import Dict, List, Set
from dataclasses import dataclass


@dataclass
class ComplianceMapping:
    """Mapping of an OWASP category to a compliance framework control."""

    framework: str
    control_id: str
    control_name: str
    category: str
    description: str


# Compliance framework mappings for each OWASP LLM category
COMPLIANCE_MAPPINGS: Dict[str, List[ComplianceMapping]] = {
    "owasp_llm01": [  # Prompt Injection
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-1.2",
            control_name="Risk Management",
            category="Govern",
            description="Risks and benefits of AI systems are identified, assessed, and managed",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MAP-3.3",
            control_name="AI System Capabilities",
            category="Map",
            description="Potential adverse impacts from AI systems are identified and assessed",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MEASURE-2.3",
            control_name="AI System Performance",
            category="Measure",
            description="AI system behavior and performance are monitored and evaluated",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MANAGE-2.3",
            control_name="Risk Treatment",
            category="Manage",
            description="Mechanisms are in place to manage risks from AI system inputs",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="6.2.1",
            control_name="AI Risk Assessment",
            category="Planning",
            description="Organization shall assess risks associated with AI system operation",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.2",
            control_name="AI System Input/Output Management",
            category="Operation",
            description="Controls for managing AI system inputs and preventing manipulation",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 15",
            control_name="Accuracy, Robustness and Cybersecurity",
            category="High-Risk AI Requirements",
            description="AI systems shall be resilient against harmful manipulation",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-5",
            control_name="Data Integrity",
            category="Protect",
            description="Protections against data integrity threats implemented",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.1",
            control_name="Logical Access - Input Validation",
            category="Common Criteria",
            description="Entity implements controls over system inputs to prevent unauthorized manipulation",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.8.3",
            control_name="Input Data Validation",
            category="Annex A",
            description="Input data validation controls to prevent injection attacks",
        ),
    ],
    "owasp_llm02": [  # Sensitive Information Disclosure
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-5.1",
            control_name="Privacy Management",
            category="Govern",
            description="Processes are established to manage AI system privacy risks",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MAP-5.1",
            control_name="Privacy Impact",
            category="Map",
            description="Potential privacy impacts from AI systems are identified",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="7.3",
            control_name="Data Management for AI",
            category="Support",
            description="Controls for managing sensitive data in AI training and operations",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 10",
            control_name="Data and Data Governance",
            category="High-Risk AI Requirements",
            description="Training data shall be subject to appropriate data governance",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-1",
            control_name="Data-at-Rest Protection",
            category="Protect",
            description="Data at rest is protected through appropriate mechanisms",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-2",
            control_name="Data-in-Transit Protection",
            category="Protect",
            description="Data in transit is protected through appropriate mechanisms",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.7",
            control_name="Confidentiality",
            category="Common Criteria",
            description="Entity implements controls to prevent unauthorized disclosure of sensitive information",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.8.11",
            control_name="Data Masking",
            category="Annex A",
            description="Data masking is used in accordance with access control policy",
        ),
    ],
    "owasp_llm03": [  # Supply Chain Vulnerabilities
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-1.3",
            control_name="Third-Party Risk",
            category="Govern",
            description="Processes to address AI risks associated with third parties",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MAP-1.5",
            control_name="Supply Chain Dependencies",
            category="Map",
            description="Dependencies and relationships with external parties are documented",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.4",
            control_name="Supply Chain Management",
            category="Operation",
            description="Controls for managing AI system supply chain risks",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 11",
            control_name="Technical Documentation",
            category="High-Risk AI Requirements",
            description="Documentation of data sources and model provenance required",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="ID.SC-1",
            control_name="Supply Chain Risk Management",
            category="Identify",
            description="Cyber supply chain risk management processes identified",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="ID.SC-2",
            control_name="Supplier Assessment",
            category="Identify",
            description="Suppliers and third-party partners assessed using a risk-based approach",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC9.2",
            control_name="Vendor Management",
            category="Common Criteria",
            description="Entity implements controls over vendor and business partner risks",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.19",
            control_name="Supplier Relationships",
            category="Annex A",
            description="Security in supplier relationships and supply chain managed",
        ),
    ],
    "owasp_llm04": [  # Model Denial of Service
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MANAGE-4.1",
            control_name="Resource Management",
            category="Manage",
            description="AI system resource usage is monitored and managed",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.5",
            control_name="AI System Performance Monitoring",
            category="Operation",
            description="Monitoring of AI system performance and resource utilization",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-4",
            control_name="Availability",
            category="Protect",
            description="Adequate capacity to ensure availability is maintained",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="DE.CM-8",
            control_name="Performance Monitoring",
            category="Detect",
            description="System performance is monitored to detect anomalies",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="A1.2",
            control_name="System Availability",
            category="Availability",
            description="Entity implements controls to meet system availability commitments",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.8.6",
            control_name="Capacity Management",
            category="Annex A",
            description="Capacity management to ensure required system performance",
        ),
    ],
    "owasp_llm05": [  # Insecure Output Handling
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MANAGE-2.4",
            control_name="Output Validation",
            category="Manage",
            description="AI system outputs are validated before use in downstream systems",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.2",
            control_name="AI System Input/Output Management",
            category="Operation",
            description="Controls for managing and validating AI system outputs",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 15",
            control_name="Accuracy, Robustness and Cybersecurity",
            category="High-Risk AI Requirements",
            description="AI systems shall implement appropriate cybersecurity measures",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-5",
            control_name="Data Integrity",
            category="Protect",
            description="Protections against data integrity threats implemented",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.1",
            control_name="Output Validation",
            category="Common Criteria",
            description="Entity implements controls over system outputs to prevent injection",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.8.3",
            control_name="Output Data Validation",
            category="Annex A",
            description="Output data validation controls to prevent injection attacks",
        ),
    ],
    "owasp_llm06": [  # Insecure Plugin/Tool Use
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-2.1",
            control_name="Authorization & Access Control",
            category="Govern",
            description="Authorization and access control mechanisms for AI systems",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MANAGE-3.1",
            control_name="Integration Security",
            category="Manage",
            description="Security of AI system integrations and extensions managed",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.3",
            control_name="AI System Integration Management",
            category="Operation",
            description="Controls for secure integration of AI system components",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.AC-1",
            control_name="Access Control",
            category="Protect",
            description="Identities and credentials are issued and managed",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.AC-4",
            control_name="Least Privilege",
            category="Protect",
            description="Access permissions follow least privilege principle",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.2",
            control_name="Authorization",
            category="Common Criteria",
            description="Entity implements controls to ensure proper authorization",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.15",
            control_name="Access Control",
            category="Annex A",
            description="Access control policy to manage authorization",
        ),
    ],
    "owasp_llm07": [  # System Prompt Leakage
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-5.1",
            control_name="Privacy & Information Protection",
            category="Govern",
            description="Processes to manage privacy and information disclosure risks",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MAP-5.2",
            control_name="Configuration Protection",
            category="Map",
            description="Sensitive configuration and system details are protected",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="7.4",
            control_name="Configuration Management",
            category="Support",
            description="AI system configuration information is protected",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-1",
            control_name="Information Protection",
            category="Protect",
            description="Sensitive information is protected appropriately",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.7",
            control_name="Confidentiality",
            category="Common Criteria",
            description="Entity protects confidential information from unauthorized disclosure",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.12",
            control_name="Classification of Information",
            category="Annex A",
            description="Information classification and protection requirements",
        ),
    ],
    "owasp_llm08": [  # Excessive Agency
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-2.1",
            control_name="Authorization Framework",
            category="Govern",
            description="Authorization mechanisms limit AI system capabilities appropriately",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MANAGE-3.2",
            control_name="Autonomy Boundaries",
            category="Manage",
            description="Boundaries on AI system autonomy and decision-making authority",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.6",
            control_name="AI System Autonomy Management",
            category="Operation",
            description="Controls over AI system autonomous capabilities and permissions",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 14",
            control_name="Human Oversight",
            category="High-Risk AI Requirements",
            description="High-risk AI systems shall have appropriate human oversight measures",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.AC-4",
            control_name="Least Privilege",
            category="Protect",
            description="Access permissions follow principle of least privilege",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.3",
            control_name="Privilege Management",
            category="Common Criteria",
            description="Entity implements controls to manage privileged access appropriately",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.18",
            control_name="Access Rights",
            category="Annex A",
            description="Access rights are provisioned following least privilege",
        ),
    ],
    "owasp_llm09": [  # Overreliance
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-4.1",
            control_name="Transparency & Explainability",
            category="Govern",
            description="AI system limitations and uncertainties are communicated to users",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MEASURE-2.7",
            control_name="Output Verification",
            category="Measure",
            description="AI system outputs are verified for accuracy and reliability",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="8.7",
            control_name="AI System Output Verification",
            category="Operation",
            description="Verification and validation of AI system outputs",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 13",
            control_name="Transparency and User Information",
            category="High-Risk AI Requirements",
            description="Users must be informed of AI system capabilities and limitations",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 14",
            control_name="Human Oversight",
            category="High-Risk AI Requirements",
            description="Human oversight to prevent overreliance on AI systems",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC2.2",
            control_name="Communication with Users",
            category="Common Criteria",
            description="Entity communicates system limitations and responsibilities to users",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.1",
            control_name="Information Security Policies",
            category="Annex A",
            description="Policies address appropriate use and limitations of systems",
        ),
    ],
    "owasp_llm10": [  # Model Theft
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="GOVERN-1.4",
            control_name="Intellectual Property Protection",
            category="Govern",
            description="AI system intellectual property is identified and protected",
        ),
        ComplianceMapping(
            framework="NIST AI RMF",
            control_id="MAP-1.6",
            control_name="Asset Management",
            category="Map",
            description="AI system assets including models are inventoried and protected",
        ),
        ComplianceMapping(
            framework="ISO/IEC 42001",
            control_id="7.5",
            control_name="AI Asset Protection",
            category="Support",
            description="AI system assets including models are protected from theft",
        ),
        ComplianceMapping(
            framework="EU AI Act",
            control_id="Article 11",
            control_name="Technical Documentation",
            category="High-Risk AI Requirements",
            description="Technical documentation includes model protection measures",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.DS-1",
            control_name="Data-at-Rest Protection",
            category="Protect",
            description="Sensitive assets including models are protected at rest",
        ),
        ComplianceMapping(
            framework="NIST CSF 2.0",
            control_id="PR.AC-1",
            control_name="Access Control",
            category="Protect",
            description="Access to sensitive assets is controlled and monitored",
        ),
        ComplianceMapping(
            framework="SOC 2",
            control_id="CC6.6",
            control_name="Logical Access - Monitoring",
            category="Common Criteria",
            description="Entity monitors access to sensitive assets for unauthorized activity",
        ),
        ComplianceMapping(
            framework="ISO/IEC 27001",
            control_id="A.5.9",
            control_name="Inventory of Information Assets",
            category="Annex A",
            description="Assets including AI models are inventoried and protected",
        ),
    ],
}


def get_compliance_mappings(owasp_marker: str) -> List[ComplianceMapping]:
    """Get all compliance framework mappings for an OWASP category.

    Args:
        owasp_marker: OWASP marker name (e.g., 'owasp_llm01')

    Returns:
        List of compliance mappings for the category
    """
    return COMPLIANCE_MAPPINGS.get(owasp_marker, [])


def get_frameworks_covered(owasp_markers: List[str]) -> Set[str]:
    """Get unique set of compliance frameworks covered by test results.

    Args:
        owasp_markers: List of OWASP markers from test results

    Returns:
        Set of framework names covered
    """
    frameworks = set()
    for marker in owasp_markers:
        mappings = get_compliance_mappings(marker)
        for mapping in mappings:
            frameworks.add(mapping.framework)
    return frameworks


def get_framework_coverage(
    owasp_markers: List[str], framework: str
) -> List[ComplianceMapping]:
    """Get all controls covered for a specific framework.

    Args:
        owasp_markers: List of OWASP markers from test results
        framework: Framework name to filter by

    Returns:
        List of compliance mappings for the specified framework
    """
    coverage = []
    for marker in owasp_markers:
        mappings = get_compliance_mappings(marker)
        coverage.extend([m for m in mappings if m.framework == framework])
    return coverage


def get_compliance_summary(owasp_markers: List[str]) -> Dict[str, Dict[str, int]]:
    """Generate summary of compliance coverage across frameworks.

    Args:
        owasp_markers: List of OWASP markers from test results

    Returns:
        Dictionary mapping framework names to coverage statistics
    """
    summary = {}
    frameworks = get_frameworks_covered(owasp_markers)

    for framework in frameworks:
        coverage = get_framework_coverage(owasp_markers, framework)
        unique_controls = set((m.control_id, m.control_name) for m in coverage)

        summary[framework] = {
            "total_controls": len(unique_controls),
            "categories_covered": len(set(m.category for m in coverage)),
            "owasp_mapped": len(set(owasp_markers)),
        }

    return summary
