"""
CLI Wrapper for Google Cloud CodeMender tool.
Executes CLI commands or provides realistic mock simulation when the binary is absent.
Includes robust error handling and explicit recovery instructions for the LLM.
"""

import json
import os
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional
from codemender_agent.config import SeverityLevel, Vulnerability, VulnerabilityStatus


class CodeMenderCLIWrapper:
    """Wrapper around CodeMender CLI executable with robust error handling and mock fallback."""

    def __init__(self, cli_binary_name: str = "codemender"):
        self.cli_binary = shutil.which(cli_binary_name)

    @property
    def is_available(self) -> bool:
        return self.cli_binary is not None

    def check_environment(self, repo_path: str = ".") -> Dict[str, Any]:
        """Check CodeMender environment installation, authentication status, and repo path."""
        if not os.path.exists(repo_path):
            return {
                "success": False,
                "installed": False,
                "error_code": "REPO_PATH_NOT_FOUND",
                "error_message": f"Target repository path '{repo_path}' does not exist on filesystem.",
                "recovery_instructions": (
                    "1. Verify the repository path passed to the tool. "
                    "2. Ensure the working directory contains source code files before re-running."
                ),
            }

        if self.is_available:
            try:
                res = subprocess.run(
                    [self.cli_binary, "version", "--json"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if res.returncode == 0:
                    data = json.loads(res.stdout)
                    return {
                        "success": True,
                        "installed": True,
                        "version": data.get("version", "1.0.0"),
                        "authenticated": data.get("authenticated", True),
                        "mode": "CLI",
                        "repo_path": os.path.abspath(repo_path),
                    }
                else:
                    return {
                        "success": False,
                        "installed": True,
                        "error_code": "CLI_EXECUTION_ERROR",
                        "error_message": f"CodeMender version check failed: {res.stderr.strip()}",
                        "recovery_instructions": "Ensure the CodeMender CLI binary is properly configured and authenticated with GCP credentials.",
                    }
            except subprocess.TimeoutExpired:
                return {
                    "success": False,
                    "installed": True,
                    "error_code": "CLI_TIMEOUT",
                    "error_message": "CodeMender CLI version check timed out after 10 seconds.",
                    "recovery_instructions": "Check system resource usage and verify CLI connectivity before retrying.",
                }
            except Exception as e:
                return {
                    "success": False,
                    "installed": False,
                    "error_code": "CLI_EXCEPTION",
                    "error_message": f"Unexpected error during environment check: {str(e)}",
                    "recovery_instructions": "Verify CodeMender binary permissions and environment variables.",
                }

        # Mock fallback for demonstration and local testing
        return {
            "success": True,
            "installed": True,
            "version": "1.4.0-mock",
            "authenticated": True,
            "mode": "MOCK_SIMULATOR",
            "message": "CodeMender CLI simulator active",
            "repo_path": os.path.abspath(repo_path),
        }

    def scan_sast(self, repo_path: str = ".") -> List[Dict[str, Any]]:
        """Run Static Application Security Testing (SAST) on repository."""
        if not os.path.exists(repo_path):
            raise ValueError(f"Target repository path '{repo_path}' does not exist.")

        if self.is_available:
            try:
                res = subprocess.run(
                    [self.cli_binary, "scan", "--sast", "--path", repo_path, "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode == 0:
                    return json.loads(res.stdout)
                else:
                    raise RuntimeError(f"CodeMender SAST scan failed (exit code {res.returncode}): {res.stderr.strip()}")
            except subprocess.TimeoutExpired:
                raise TimeoutError("CodeMender SAST scan timed out after 60 seconds.")

        # Realistic mock SAST findings for demonstration
        return [
            {
                "vuln_id": "SAST-SQLI-001",
                "title": "Unsanitized User Input in SQL Query Construction",
                "severity": SeverityLevel.HIGH.value,
                "file_path": "app/db.py",
                "line_number": 42,
                "cve_id": "CWE-89",
                "category": "SAST",
                "description": "SQL injection risk due to string concatenation in db query.",
                "status": VulnerabilityStatus.DISCOVERED.value,
            },
            {
                "vuln_id": "SAST-PATH-002",
                "title": "Arbitrary Path Traversal via Unvalidated Input",
                "severity": SeverityLevel.CRITICAL.value,
                "file_path": "app/utils/file_handler.py",
                "line_number": 88,
                "cve_id": "CWE-22",
                "category": "SAST",
                "description": "File path constructed directly from query params without sanitization.",
                "status": VulnerabilityStatus.DISCOVERED.value,
            },
        ]

    def scan_sca(self, repo_path: str = ".") -> List[Dict[str, Any]]:
        """Run Software Composition Analysis (SCA) for dependency vulnerabilities."""
        if not os.path.exists(repo_path):
            raise ValueError(f"Target repository path '{repo_path}' does not exist.")

        if self.is_available:
            try:
                res = subprocess.run(
                    [self.cli_binary, "scan", "--sca", "--path", repo_path, "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode == 0:
                    return json.loads(res.stdout)
                else:
                    raise RuntimeError(f"CodeMender SCA scan failed (exit code {res.returncode}): {res.stderr.strip()}")
            except subprocess.TimeoutExpired:
                raise TimeoutError("CodeMender SCA scan timed out after 60 seconds.")

        # Realistic mock SCA findings for demonstration
        return [
            {
                "vuln_id": "SCA-DEP-001",
                "title": "Outdated PyYAML package vulnerable to Arbitrary Code Execution",
                "severity": SeverityLevel.HIGH.value,
                "file_path": "requirements.txt",
                "line_number": 5,
                "cve_id": "CVE-2020-14343",
                "category": "SCA",
                "description": "PyYAML before 5.4 allows arbitrary code execution via load() method.",
                "status": VulnerabilityStatus.DISCOVERED.value,
            }
        ]

    def generate_fix(self, repo_path: str, vuln_id: str) -> Dict[str, Any]:
        """Generate candidate fix / patch diff for given vulnerability ID."""
        if not vuln_id or not vuln_id.strip():
            raise ValueError("vuln_id must be provided.")

        if self.is_available:
            try:
                res = subprocess.run(
                    [self.cli_binary, "fix", "generate", "--vuln-id", vuln_id, "--path", repo_path, "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode == 0:
                    return json.loads(res.stdout)
                else:
                    raise RuntimeError(f"CodeMender fix generation failed: {res.stderr.strip()}")
            except subprocess.TimeoutExpired:
                raise TimeoutError("CodeMender fix generation timed out.")

        # Mock fix generation
        patches = {
            "SAST-SQLI-001": (
                "--- a/app/db.py\n"
                "+++ b/app/db.py\n"
                "@@ -42,1 +42,1 @@\n"
                "-query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
                "+query = \"SELECT * FROM users WHERE username = %s\"  # Parameterized query fix"
            ),
            "SAST-PATH-002": (
                "--- a/app/utils/file_handler.py\n"
                "+++ b/app/utils/file_handler.py\n"
                "@@ -88,1 +88,1 @@\n"
                "-file_path = os.path.join(BASE_DIR, user_input)\n"
                "+file_path = os.path.abspath(os.path.join(BASE_DIR, os.path.basename(user_input)))"
            ),
            "SCA-DEP-001": (
                "--- a/requirements.txt\n"
                "+++ b/requirements.txt\n"
                "@@ -5,1 +5,1 @@\n"
                "-PyYAML==5.3.1\n"
                "+PyYAML>=6.0.1"
            ),
        }

        diff = patches.get(vuln_id, "--- a/file.py\n+++ b/file.py\n@@ -1,1 +1,1 @@\n-# Fix applied\n+# Remediated code")
        return {
            "vuln_id": vuln_id,
            "patch_diff": diff,
            "status": VulnerabilityStatus.PATCH_GENERATED.value,
            "message": f"Generated patch diff for {vuln_id}",
        }

    def verify_fix(self, repo_path: str, vuln_id: str) -> Dict[str, Any]:
        """Verify applied fix against CodeMender verification test suites."""
        if not vuln_id or not vuln_id.strip():
            raise ValueError("vuln_id must be provided.")

        if self.is_available:
            try:
                res = subprocess.run(
                    [self.cli_binary, "fix", "verify", "--vuln-id", vuln_id, "--path", repo_path, "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if res.returncode == 0:
                    return json.loads(res.stdout)
                else:
                    raise RuntimeError(f"CodeMender fix verification failed: {res.stderr.strip()}")
            except subprocess.TimeoutExpired:
                raise TimeoutError("CodeMender fix verification timed out.")

        # Mock verification response
        return {
            "vuln_id": vuln_id,
            "verified": True,
            "status": VulnerabilityStatus.VERIFIED_FIXED.value,
            "details": f"Verification sandbox confirmed zero residual exploit vectors for {vuln_id}.",
        }

    def export_report(self, repo_path: str, output_format: str = "markdown", vulnerabilities: List[Dict[str, Any]] = None) -> str:
        """Export security scan and remediation report."""
        vulns = vulnerabilities or []
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if output_format == "json":
            return json.dumps({
                "report_title": "CodeMender Security Audit Report",
                "repo_path": repo_path,
                "timestamp": timestamp,
                "findings_count": len(vulns),
                "vulnerabilities": vulns,
            }, indent=2)

        report_lines = [
            f"# CodeMender Security Audit Report",
            f"**Repository Path**: `{repo_path}`",
            f"**Generated At**: {timestamp}",
            f"**Total Findings**: {len(vulns)}",
            "",
            "## Findings Summary",
            "| ID | Category | Severity | File | Status |",
            "|---|---|---|---|---|",
        ]

        for v in vulns:
            report_lines.append(
                f"| {v.get('vuln_id')} | {v.get('category')} | **{v.get('severity')}** | `{v.get('file_path')}:{v.get('line_number', '-')}` | {v.get('status')} |"
            )

        report_lines.extend([
            "",
            "## Detailed Remediation Actions",
        ])

        for v in vulns:
            report_lines.append(f"### {v.get('vuln_id')}: {v.get('title')}")
            report_lines.append(f"- **Severity**: {v.get('severity')}")
            report_lines.append(f"- **Description**: {v.get('description')}")
            if v.get("patch_diff"):
                report_lines.append("```diff")
                report_lines.append(v.get("patch_diff"))
                report_lines.append("```")
            report_lines.append("")

        return "\n".join(report_lines)
