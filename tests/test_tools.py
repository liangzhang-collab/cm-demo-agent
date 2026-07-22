"""
Unit tests for CodeMender function tools, Pydantic schemas, and error recovery.
"""

import json
import pytest
from codemender_agent.tools.cli_wrapper import CodeMenderCLIWrapper
from codemender_agent.tools.codemender_tools import (
    check_codemender_env,
    scan_sast_vulnerabilities,
    scan_sca_dependencies,
    generate_vulnerability_fix,
    verify_vulnerability_fix,
    export_security_report,
    request_human_approval,
)


def test_cli_wrapper_environment():
    cli = CodeMenderCLIWrapper()
    env = cli.check_environment()
    assert "installed" in env
    assert env["installed"] is True


def test_tool_check_env():
    res_str = check_codemender_env(".")
    data = json.loads(res_str)
    assert data.get("installed") is True


def test_tool_scan_sast():
    res_str = scan_sast_vulnerabilities(".")
    data = json.loads(res_str)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "vuln_id" in data[0]


def test_tool_scan_sca():
    res_str = scan_sca_dependencies(".")
    data = json.loads(res_str)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "vuln_id" in data[0]


def test_tool_generate_and_verify_fix():
    gen_str = generate_vulnerability_fix(".", "SAST-SQLI-001")
    gen_data = json.loads(gen_str)
    assert gen_data["vuln_id"] == "SAST-SQLI-001"
    assert "patch_diff" in gen_data

    ver_str = verify_vulnerability_fix(".", "SAST-SQLI-001")
    ver_data = json.loads(ver_str)
    assert ver_data["verified"] is True


def test_tool_error_recovery_instructions():
    # Test invalid vuln_id (empty string)
    err_str = generate_vulnerability_fix(".", "")
    err_data = json.loads(err_str)
    assert err_data["success"] is False
    assert "recovery_instructions" in err_data
    assert len(err_data["recovery_instructions"]) > 10


def test_tool_export_report():
    vulns = [
        {
            "vuln_id": "SAST-SQLI-001",
            "title": "SQL Injection",
            "severity": "HIGH",
            "file_path": "app/db.py",
            "line_number": 42,
            "category": "SAST",
            "status": "VERIFIED_FIXED",
            "description": "SQL Injection vulnerability",
        }
    ]
    report = export_security_report(".", json.dumps(vulns), "markdown")
    assert "# CodeMender Security Audit Report" in report
    assert "SAST-SQLI-001" in report


def test_request_human_approval_tool():
    res_str = request_human_approval(
        action_type="APPLY_CRITICAL_PATCH",
        vuln_id="SAST-SQLI-001",
        patch_diff="--- a/db.py\n+++ b/db.py",
        reason="Remediate SQL injection before production release",
    )
    data = json.loads(res_str)
    assert data["approved"] is True
    assert data["status"] == "APPROVED"
