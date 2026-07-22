"""
ADK Custom Function Tools for CodeMender CLI operations.
Used by CodeMender agents for scanning, fixing, verifying, and reporting codebase vulnerabilities.
"""

import json
from typing import Any, Dict, List, Optional
from codemender_agent.tools.cli_wrapper import CodeMenderCLIWrapper

_cli = CodeMenderCLIWrapper()


def check_codemender_env() -> str:
    """
    Validates CodeMender CLI environment installation, authentication, and system readiness.
    
    Returns:
        JSON string containing installation status, CLI version, and mode.
    """
    res = _cli.check_environment()
    return json.dumps(res, indent=2)


def scan_sast_vulnerabilities(repo_path: str = ".") -> str:
    """
    Executes Static Application Security Testing (SAST) on the target repository code.
    
    Args:
        repo_path: Path to the target local repository directory (defaults to current dir '.').
        
    Returns:
        JSON array string of detected static code vulnerabilities (e.g. SQL injection, path traversal).
    """
    findings = _cli.scan_sast(repo_path)
    return json.dumps(findings, indent=2)


def scan_sca_dependencies(repo_path: str = ".") -> str:
    """
    Executes Software Composition Analysis (SCA) on project dependencies (e.g., requirements.txt, package.json).
    
    Args:
        repo_path: Path to target local repository directory.
        
    Returns:
        JSON array string of detected package vulnerability CVEs and outdated dependency risks.
    """
    findings = _cli.scan_sca(repo_path)
    return json.dumps(findings, indent=2)


def generate_vulnerability_fix(repo_path: str, vuln_id: str) -> str:
    """
    Generates an automated code patch/fix for a specific vulnerability ID.
    
    Args:
        repo_path: Path to target local repository directory.
        vuln_id: Unique vulnerability ID to generate a patch for (e.g., 'SAST-SQLI-001').
        
    Returns:
        JSON string containing the patch diff and patch generation status.
    """
    fix_res = _cli.generate_fix(repo_path, vuln_id)
    return json.dumps(fix_res, indent=2)


def verify_vulnerability_fix(repo_path: str, vuln_id: str) -> str:
    """
    Executes automated verification sandboxes to confirm that a generated patch remediated the vulnerability without regressions.
    
    Args:
        repo_path: Path to target local repository directory.
        vuln_id: Unique vulnerability ID to verify.
        
    Returns:
        JSON string with verification status (verified: true/false) and details.
    """
    verify_res = _cli.verify_fix(repo_path, vuln_id)
    return json.dumps(verify_res, indent=2)


def export_security_report(repo_path: str, vulnerabilities_json: str, output_format: str = "markdown") -> str:
    """
    Exports a structured security audit and remediation report for the repository.
    
    Args:
        repo_path: Target repository path.
        vulnerabilities_json: JSON string of vulnerability records.
        output_format: Output format ('markdown' or 'html').
        
    Returns:
        Formatted markdown report string.
    """
    try:
        vulns = json.loads(vulnerabilities_json)
    except Exception:
        vulns = []
    
    return _cli.export_report(repo_path, output_format=output_format, vulnerabilities=vulns)
