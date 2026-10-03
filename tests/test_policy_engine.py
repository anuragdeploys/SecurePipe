from pathlib import Path
import json

from policy_engine import parse_sarif_findings, evaluate_vulnerabilities


def write_sarif(tmp_path, results):
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "version": "0.75.0",
                    }
                },
                "results": results,
            }
        ],
    }

    path = tmp_path / "test.sarif"
    path.write_text(json.dumps(sarif))
    return path


def test_parse_high_vulnerability_with_fixed_version(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-001",
            "level": "error",
            "message": {
                "text": (
                    "Package: test-package\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-001\n"
                    "Severity: HIGH\n"
                    "Fixed Version: 1.2.0\n"
                    "Link: https://example.com/CVE-TEST-001"
                )
            },
        }
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert len(findings) == 1

    finding = findings[0]

    assert finding["id"] == "CVE-TEST-001"
    assert finding["package"] == "test-package"
    assert finding["installed_version"] == "1.0.0"
    assert finding["severity"] == "HIGH"
    assert finding["fixed_version"] == "1.2.0"
    assert finding["fix_available"] is True


def test_parse_high_vulnerability_without_fixed_version(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-002",
            "level": "error",
            "message": {
                "text": (
                    "Package: test-package\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-002\n"
                    "Severity: HIGH\n"
                    "Fixed Version: \n"
                    "Link: https://example.com/CVE-TEST-002"
                )
            },
        }
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert len(findings) == 1

    finding = findings[0]

    assert finding["severity"] == "HIGH"
    assert finding["fixed_version"] == ""
    assert finding["fix_available"] is False


def test_parse_critical_vulnerability(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-003",
            "level": "error",
            "message": {
                "text": (
                    "Package: critical-package\n"
                    "Installed Version: 2.0.0\n"
                    "Vulnerability CVE-TEST-003\n"
                    "Severity: CRITICAL\n"
                    "Fixed Version: 2.1.0\n"
                )
            },
        }
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["fix_available"] is True


def test_parse_medium_and_low_vulnerabilities(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-004",
            "level": "warning",
            "message": {
                "text": (
                    "Package: medium-package\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-004\n"
                    "Severity: MEDIUM\n"
                    "Fixed Version: 1.1.0\n"
                )
            },
        },
        {
            "ruleId": "CVE-TEST-005",
            "level": "note",
            "message": {
                "text": (
                    "Package: low-package\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-005\n"
                    "Severity: LOW\n"
                    "Fixed Version: \n"
                )
            },
        },
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert len(findings) == 2

    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["fix_available"] is True

    assert findings[1]["severity"] == "LOW"
    assert findings[1]["fix_available"] is False


def test_parser_uses_trivy_severity_not_sarif_level(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-006",
            "level": "error",
            "message": {
                "text": (
                    "Package: test-package\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-006\n"
                    "Severity: HIGH\n"
                    "Fixed Version: \n"
                )
            },
        }
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["severity"] != "CRITICAL"


def test_parser_handles_multiple_findings(tmp_path):
    results = [
        {
            "ruleId": "CVE-TEST-007",
            "level": "error",
            "message": {
                "text": (
                    "Package: package-one\n"
                    "Installed Version: 1.0.0\n"
                    "Vulnerability CVE-TEST-007\n"
                    "Severity: HIGH\n"
                    "Fixed Version: \n"
                )
            },
        },
        {
            "ruleId": "CVE-TEST-007",
            "level": "error",
            "message": {
                "text": (
                    "Package: package-two\n"
                    "Installed Version: 2.0.0\n"
                    "Vulnerability CVE-TEST-007\n"
                    "Severity: HIGH\n"
                    "Fixed Version: \n"
                )
            },
        },
    ]

    findings = parse_sarif_findings(write_sarif(tmp_path, results))

    assert len(findings) == 2
    assert findings[0]["package"] == "package-one"
    assert findings[1]["package"] == "package-two"


def make_finding(severity, fix_available):
    return {
        "id": f"CVE-TEST-{severity}",
        "package": "test-package",
        "installed_version": "1.0.0",
        "severity": severity,
        "fixed_version": "1.1.0" if fix_available else "",
        "fix_available": fix_available,
    }


def default_policy():
    return {
        "max_critical": 0,
        "max_high": 0,
        "max_medium": 10,
        "max_low": 50,
        "block_on_critical": True,
        "block_on_high": True,
    }


def test_policy_blocks_fixable_critical():
    findings = [
        make_finding("CRITICAL", True),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Fixable CRITICAL vulnerability found"


def test_policy_blocks_fixable_high():
    findings = [
        make_finding("HIGH", True),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Fixable HIGH vulnerability found"


def test_policy_reports_unfixable_critical():
    findings = [
        make_finding("CRITICAL", False),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_reports_unfixable_high():
    findings = [
        make_finding("HIGH", False),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_allows_unfixable_medium_findings_within_threshold():
    findings = [
        make_finding("MEDIUM", False),
        make_finding("MEDIUM", False),
        make_finding("MEDIUM", False),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_blocks_fixable_medium_findings_above_threshold():
    findings = [
        make_finding("MEDIUM", True)
        for _ in range(11)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "BLOCK"


def test_policy_allows_fixable_medium_findings_within_threshold():
    findings = [
        make_finding("MEDIUM", True)
        for _ in range(10)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "PASS"


def test_policy_reports_unfixable_medium_findings_above_threshold():
    findings = [
        make_finding("MEDIUM", False)
        for _ in range(11)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_allows_unfixable_low_findings_within_threshold():
    findings = [
        make_finding("LOW", False)
        for _ in range(10)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_blocks_fixable_low_findings_above_threshold():
    findings = [
        make_finding("LOW", True)
        for _ in range(51)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "BLOCK"


def test_policy_allows_fixable_low_findings_within_threshold():
    findings = [
        make_finding("LOW", True)
        for _ in range(50)
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "PASS"


def test_load_policy(tmp_path):
    policy_file = tmp_path / "container.json"

    policy_file.write_text(
        json.dumps(
            {
                "max_critical": 0,
                "max_high": 0,
                "max_medium": 10,
                "max_low": 50,
                "block_on_critical": True,
                "block_on_high": True,
                "ignored_vulnerabilities": [],
            }
        )
    )

    from policy_engine import load_policy

    policy = load_policy(policy_file)

    assert policy["max_critical"] == 0
    assert policy["max_high"] == 0
    assert policy["max_medium"] == 10
    assert policy["max_low"] == 50
    assert policy["block_on_critical"] is True
    assert policy["block_on_high"] is True
    assert policy["ignored_vulnerabilities"] == []


def test_load_policy_rejects_missing_file(tmp_path):
    from policy_engine import load_policy

    missing_file = tmp_path / "missing.json"

    try:
        load_policy(missing_file)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Expected FileNotFoundError")


def test_policy_ignores_configured_vulnerability():
    findings = [
        {
            "id": "CVE-TEST-001",
            "package": "test-package",
            "installed_version": "1.0.0",
            "severity": "HIGH",
            "fixed_version": "1.1.0",
            "fix_available": True,
        }
    ]

    policy = default_policy()
    policy["ignored_vulnerabilities"] = ["CVE-TEST-001"]

    result = evaluate_vulnerabilities(findings, policy)

    assert result["decision"] == "PASS"
    assert result["counts"]["HIGH"] == 0


def test_policy_does_not_ignore_unlisted_vulnerability():
    findings = [
        {
            "id": "CVE-TEST-002",
            "package": "test-package",
            "installed_version": "1.0.0",
            "severity": "HIGH",
            "fixed_version": "1.1.0",
            "fix_available": True,
        }
    ]

    policy = default_policy()
    policy["ignored_vulnerabilities"] = ["CVE-TEST-001"]

    result = evaluate_vulnerabilities(findings, policy)

    assert result["decision"] == "BLOCK"
    assert result["counts"]["HIGH"] == 1


def test_policy_blocks_fixable_critical_from_fixture():
    fixture_path = Path("tests/fixtures/policy_findings.json")

    with fixture_path.open("r", encoding="utf-8") as file:
        findings = json.load(file)

    policy = default_policy()

    result = evaluate_vulnerabilities(findings, policy)

    assert result["decision"] == "BLOCK"
    assert result["reason"] == "Fixable CRITICAL vulnerability found"


def test_policy_reports_unfixable_high_from_fixture():
    fixture_path = Path("tests/fixtures/policy_findings.json")

    with fixture_path.open("r", encoding="utf-8") as file:
        findings = json.load(file)

    findings = [
        finding
        for finding in findings
        if finding["id"] == "CVE-TEST-HIGH-UNFIXED"
    ]

    policy = default_policy()

    result = evaluate_vulnerabilities(findings, policy)

    assert result["decision"] == "REPORT"
    assert result["reason"] == "Currently unfixed vulnerabilities found"


def test_policy_passes_medium_finding_within_fixture_threshold():
    fixture_path = Path("tests/fixtures/policy_findings.json")

    with fixture_path.open("r", encoding="utf-8") as file:
        findings = json.load(file)

    findings = [
        finding
        for finding in findings
        if finding["id"] == "CVE-TEST-MEDIUM"
    ]

    policy = default_policy()

    result = evaluate_vulnerabilities(findings, policy)

    assert result["decision"] == "PASS"
    assert result["reason"] == "All vulnerability policy checks passed"


def test_policy_reports_unfixable_medium_and_low_findings():
    findings = [
        make_finding("MEDIUM", False),
        make_finding("LOW", False),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"


def test_policy_blocks_when_fixable_medium_exceeds_threshold_with_unfixable_findings():
    findings = [
        make_finding("MEDIUM", True)
        for _ in range(11)
    ]

    findings.extend(
        [
            make_finding("MEDIUM", False),
            make_finding("LOW", False),
        ]
    )

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "BLOCK"


def test_policy_reports_unfixable_findings_without_blocking():
    findings = [
        make_finding("HIGH", False),
        make_finding("MEDIUM", False),
        make_finding("LOW", False),
    ]

    result = evaluate_vulnerabilities(findings, default_policy())

    assert result["decision"] == "REPORT"
