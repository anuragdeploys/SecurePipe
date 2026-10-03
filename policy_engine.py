import argparse
import json
import re
import sys
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
    pattern = rf"^{re.escape(field_name)}:\s*(.*)$"

    for line in message.splitlines():
        match = re.match(pattern, line.strip())

        if match:
            return match.group(1).strip()

    return ""


def load_policy(policy_path):
    """
    Load a JSON security policy from disk.

    Returns:
        dict

    Raises:
        FileNotFoundError
        json.JSONDecodeError
    """
    policy_path = Path(policy_path)

    with policy_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_vulnerabilities(findings, policy):
    """
    Evaluate normalized vulnerability findings against security policy.

    Returns a dictionary containing:

        decision:
            PASS, REPORT, or BLOCK

        reason:
            Human-readable explanation

        counts:
            Number of applicable findings by severity
    """

    ignored_vulnerabilities = set(
        policy.get("ignored_vulnerabilities", [])
    )

    applicable_findings = [
        finding
        for finding in findings
        if finding.get("id") not in ignored_vulnerabilities
    ]

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    # Count findings BEFORE evaluating any thresholds.
    for finding in applicable_findings:
        severity = finding.get("severity")

        if severity in counts:
            counts[severity] += 1

    # ---------------------------------------------------------
    # Fixable CRITICAL vulnerabilities
    # ---------------------------------------------------------

    critical_fixable = [
        finding
        for finding in applicable_findings
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
    # Fixable HIGH vulnerabilities
    # ---------------------------------------------------------

    high_fixable = [
        finding
        for finding in applicable_findings
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
    # Unfixable CRITICAL/HIGH vulnerabilities
    # ---------------------------------------------------------

    unfixable_critical = [
        finding
        for finding in applicable_findings
        if finding.get("severity") == "CRITICAL"
        and not finding.get("fix_available")
    ]

    unfixable_high = [
        finding
        for finding in applicable_findings
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


def build_argument_parser():
    parser = argparse.ArgumentParser(
        description="Evaluate Trivy SARIF findings against a SecurePipe policy."
    )

    parser.add_argument(
        "--sarif",
        required=True,
        help="Path to the Trivy SARIF report.",
    )

    parser.add_argument(
        "--policy",
        required=True,
        help="Path to the JSON security policy.",
    )

    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        findings = parse_sarif_findings(args.sarif)
        policy = load_policy(args.policy)
        result = evaluate_vulnerabilities(findings, policy)

    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 2

    print("SecurePipe Policy Gate")
    print("======================")
    print(f"Findings: {len(findings)}")
    print(f"Decision: {result['decision']}")
    print(f"Reason: {result['reason']}")
    print(f"Counts: {result['counts']}")

    if result["decision"] == "BLOCK":
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
