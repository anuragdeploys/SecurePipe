import json
import re
from pathlib import Path


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def parse_sarif_findings(sarif_path):
    """
    Parse Trivy SARIF output into normalized vulnerability findings.

    The SARIF `level` field is NOT used as the vulnerability severity.
    Trivy reports the actual vulnerability severity inside message.text.
    """

    sarif_path = Path(sarif_path)

    with sarif_path.open("r", encoding="utf-8") as file:
        sarif = json.load(file)

    findings = []

    for run in sarif.get("runs", []):
        results = run.get("results", [])

        for result in results:
            rule_id = result.get("ruleId", "")
            message = result.get("message", {})
            text = message.get("text", "")

            finding = _parse_trivy_message(
                rule_id=rule_id,
                message=text,
            )

            if finding is not None:
                findings.append(finding)

    return findings


def _parse_trivy_message(rule_id, message):
    """
    Parse Trivy's human-readable SARIF message.
    """

    package = _extract_field(message, "Package")
    installed_version = _extract_field(message, "Installed Version")
    severity = _extract_field(message, "Severity")
    fixed_version = _extract_field(message, "Fixed Version")

    severity = severity.upper()

    if severity not in VALID_SEVERITIES:
        return None

    fixed_version = fixed_version.strip()

    return {
        "id": rule_id,
        "package": package,
        "installed_version": installed_version,
        "severity": severity,
        "fixed_version": fixed_version,
        "fix_available": bool(fixed_version),
    }


def _extract_field(message, field_name):
    """
    Extract a labelled value from Trivy's message text.
    """

    pattern = rf"^{re.escape(field_name)}:\s*(.*)$"

    for line in message.splitlines():
        match = re.match(pattern, line.strip())

        if match:
            return match.group(1).strip()

    return ""


def evaluate_vulnerabilities(findings, policy):
    """
    Evaluate normalized vulnerability findings against security policy.

    Returns a dictionary containing:

        decision:
            PASS, REPORT, or BLOCK

        reason:
            Human-readable explanation

        counts:
            Number of findings by severity
    """

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity")

        if severity in counts:
            counts[severity] += 1

    # ---------------------------------------------------------
    # Critical vulnerabilities
    # ---------------------------------------------------------

    critical_fixable = [
        finding
        for finding in findings
        if finding.get("severity") == "CRITICAL"
        and finding.get("fix_available") is True
    ]

    if critical_fixable and policy.get("block_on_critical", False):
        return {
            "decision": "BLOCK",
            "reason": "Fixable CRITICAL vulnerability found",
            "counts": counts,
        }

    # ---------------------------------------------------------
    # High vulnerabilities
    # ---------------------------------------------------------

    high_fixable = [
        finding
        for finding in findings
        if finding.get("severity") == "HIGH"
        and finding.get("fix_available") is True
    ]

    if high_fixable and policy.get("block_on_high", False):
        return {
            "decision": "BLOCK",
            "reason": "Fixable HIGH vulnerability found",
            "counts": counts,
        }

    # ---------------------------------------------------------
    # Medium threshold
    # ---------------------------------------------------------

    max_medium = policy.get("max_medium", 0)

    if counts["MEDIUM"] > max_medium:
        return {
            "decision": "BLOCK",
            "reason": (
                f"MEDIUM vulnerability count "
                f"({counts['MEDIUM']}) exceeds allowed maximum "
                f"({max_medium})"
            ),
            "counts": counts,
        }

    # ---------------------------------------------------------
    # Low threshold
    # ---------------------------------------------------------

    max_low = policy.get("max_low", 0)

    if counts["LOW"] > max_low:
        return {
            "decision": "BLOCK",
            "reason": (
                f"LOW vulnerability count "
                f"({counts['LOW']}) exceeds allowed maximum "
                f"({max_low})"
            ),
            "counts": counts,
        }

    # ---------------------------------------------------------
    # Unfixable critical/high findings are report-only
    # ---------------------------------------------------------

    unfixable_critical = [
        finding
        for finding in findings
        if finding.get("severity") == "CRITICAL"
        and not finding.get("fix_available")
    ]

    unfixable_high = [
        finding
        for finding in findings
        if finding.get("severity") == "HIGH"
        and not finding.get("fix_available")
    ]

    if unfixable_critical or unfixable_high:
        return {
            "decision": "REPORT",
            "reason": "Unfixable CRITICAL/HIGH vulnerabilities found",
            "counts": counts,
        }

    return {
        "decision": "PASS",
        "reason": "All vulnerability policy checks passed",
        "counts": counts,
    }
