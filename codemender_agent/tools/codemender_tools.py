"""
ADK Custom Function Tools for CodeMender CLI operations.
Uses strict Pydantic schemas to validate LLM inputs and returns structured JSON
with actionable recovery instructions upon any error.
"""

import json
from typing import Any, Dict, List, Optional
from pydantic import ValidationError

from codemender_agent.config import (
    CheckEnvInput,
    ExportReportInput,
    GenerateFixInput,
    HumanApprovalInput,
    ScanSastInput,
    ScanScaInput,
    SeverityLevel,
    ToolErrorResponse,
    VerifyFixInput,
)
from codemender_agent.tools.cli_wrapper import CodeMenderCLIWrapper

_cli = CodeMenderCLIWrapper()


def _format_error(error_code: str, error_message: str, recovery_instructions: str, context: Optional[Dict[str, Any]] = None) -> str:
    """Helper to return standardized structured JSON error with recovery instructions."""
    err = ToolErrorResponse(
        success=False,
        error_code=error_code,
        error_message=error_message,
        recovery_instructions=recovery_instructions,
        context=context or {},
    )
    return err.model_dump_json(indent=2)


def check_codemender_env(repo_path: str = ".") -> str:
    """
    Validates CodeMender CLI environment installation, authentication, and repository readiness.
    
    Args:
        repo_path: Path to the target local repository directory (defaults to current dir '.').
        
    Returns:
        JSON string containing environment status or actionable recovery instructions on error.
    """
    try:
        validated = CheckEnvInput(repo_path=repo_path)
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_INPUT_SCHEMA",
            error_message=f"Input validation failed: {str(ve)}",
            recovery_instructions="Provide a valid directory path string for repo_path (e.g., '.').",
        )

    res = _cli.check_environment(repo_path=validated.repo_path)
    return json.dumps(res, indent=2)


def scan_sast_vulnerabilities(repo_path: str = ".", min_severity: Optional[str] = None) -> str:
    """
    Executes Static Application Security Testing (SAST) on the target repository source code.
    
    Args:
        repo_path: Path to the target local repository directory.
        min_severity: Optional minimum severity threshold ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        
    Returns:
        JSON string array of detected static code vulnerabilities or structured error with recovery instructions.
    """
    try:
        sev = SeverityLevel(min_severity) if min_severity else None
        validated = ScanSastInput(repo_path=repo_path, min_severity=sev)
    except (ValidationError, ValueError) as e:
        return _format_error(
            error_code="INVALID_SCAN_PARAMETERS",
            error_message=f"Validation error: {str(e)}",
            recovery_instructions="Ensure repo_path exists and min_severity is one of: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'.",
        )

    try:
        findings = _cli.scan_sast(validated.repo_path)
        if validated.min_severity:
            sev_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            target_rank = sev_ranks.get(validated.min_severity.value, 1)
            findings = [f for f in findings if sev_ranks.get(f.get("severity", "LOW"), 1) >= target_rank]
        return json.dumps(findings, indent=2)
    except Exception as e:
        return _format_error(
            error_code="SAST_SCAN_FAILED",
            error_message=str(e),
            recovery_instructions=(
                "1. Verify that the repository directory exists and is accessible. "
                "2. Call check_codemender_env to confirm CodeMender CLI status. "
                "3. Retry scan_sast_vulnerabilities with a valid repository path."
            ),
            context={"repo_path": repo_path},
        )


def scan_sca_dependencies(repo_path: str = ".", manifest_file: Optional[str] = None) -> str:
    """
    Executes Software Composition Analysis (SCA) on project dependencies (e.g., requirements.txt, package.json).
    
    Args:
        repo_path: Path to target local repository directory.
        manifest_file: Optional specific manifest filename to inspect.
        
    Returns:
        JSON string array of detected package vulnerability CVEs or structured recovery error.
    """
    try:
        validated = ScanScaInput(repo_path=repo_path, manifest_file=manifest_file)
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_SCA_PARAMETERS",
            error_message=str(ve),
            recovery_instructions="Provide a valid repository path and optional manifest file path.",
        )

    try:
        findings = _cli.scan_sca(validated.repo_path)
        return json.dumps(findings, indent=2)
    except Exception as e:
        return _format_error(
            error_code="SCA_SCAN_FAILED",
            error_message=str(e),
            recovery_instructions=(
                "1. Check if dependency files (requirements.txt, package.json) exist in the repo. "
                "2. Run check_codemender_env to verify tool availability. "
                "3. Retry scan_sca_dependencies."
            ),
            context={"repo_path": repo_path},
        )


def generate_vulnerability_fix(repo_path: str = ".", vuln_id: str = "", context_lines: int = 3) -> str:
    """
    Generates an automated code patch / unified diff for a specific vulnerability ID.
    
    Args:
        repo_path: Path to target local repository directory.
        vuln_id: Unique vulnerability ID to generate a patch for (e.g., 'SAST-SQLI-001').
        context_lines: Number of surrounding context lines for the patch diff.
        
    Returns:
        JSON string containing the patch diff and status or recovery instructions on failure.
    """
    try:
        validated = GenerateFixInput(repo_path=repo_path, vuln_id=vuln_id, context_lines=context_lines)
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_VULN_ID_SCHEMA",
            error_message=f"Validation failed: {str(ve)}",
            recovery_instructions=(
                "1. Check the vulnerability ID from previous scan results (e.g., 'SAST-SQLI-001' or 'SCA-DEP-001'). "
                "2. Ensure vuln_id is a non-empty string. "
                "3. Re-invoke generate_vulnerability_fix with the valid vuln_id."
            ),
        )

    try:
        fix_res = _cli.generate_fix(validated.repo_path, validated.vuln_id)
        return json.dumps(fix_res, indent=2)
    except Exception as e:
        return _format_error(
            error_code="PATCH_GENERATION_FAILED",
            error_message=str(e),
            recovery_instructions=(
                f"Failed to generate patch for vulnerability '{vuln_id}'. "
                "1. Verify that the vulnerability ID exists in scan results. "
                "2. Check if source files are writable. "
                "3. Re-run scan_sast_vulnerabilities to refresh the vulnerability list."
            ),
            context={"vuln_id": vuln_id, "repo_path": repo_path},
        )


def verify_vulnerability_fix(repo_path: str = ".", vuln_id: str = "", sandbox_timeout: int = 60) -> str:
    """
    Executes automated verification sandboxes to confirm that a generated patch remediated the vulnerability without regressions.
    
    Args:
        repo_path: Path to target local repository directory.
        vuln_id: Unique vulnerability ID to verify.
        sandbox_timeout: Maximum timeout in seconds for verification tests.
        
    Returns:
        JSON string with verification status (verified: true/false) and details.
    """
    try:
        validated = VerifyFixInput(repo_path=repo_path, vuln_id=vuln_id, sandbox_timeout=sandbox_timeout)
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_VERIFY_INPUT",
            error_message=str(ve),
            recovery_instructions="Provide a valid vuln_id string and positive sandbox_timeout integer.",
        )

    try:
        verify_res = _cli.verify_fix(validated.repo_path, validated.vuln_id)
        return json.dumps(verify_res, indent=2)
    except Exception as e:
        return _format_error(
            error_code="VERIFICATION_FAILED",
            error_message=str(e),
            recovery_instructions=(
                f"Verification test suite failed for '{vuln_id}'. "
                "1. Inspect the generated patch diff for syntax errors or incomplete remediation. "
                "2. Call generate_vulnerability_fix again to synthesize a corrected patch. "
                "3. Re-run verify_vulnerability_fix."
            ),
            context={"vuln_id": vuln_id},
        )


def export_security_report(repo_path: str = ".", vulnerabilities_json: Optional[str] = None, output_format: str = "markdown") -> str:
    """
    Exports a structured security audit and remediation report for the repository.
    
    Args:
        repo_path: Target repository path.
        vulnerabilities_json: Optional JSON string of vulnerability records.
        output_format: Output format ('markdown', 'html', or 'json').
        
    Returns:
        Formatted security report string or recovery error.
    """
    try:
        validated = ExportReportInput(
            repo_path=repo_path,
            vulnerabilities_json=vulnerabilities_json,
            output_format=output_format,
        )
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_REPORT_CONFIG",
            error_message=str(ve),
            recovery_instructions="Ensure output_format is one of 'markdown', 'html', or 'json'.",
        )

    vulns = []
    if validated.vulnerabilities_json:
        try:
            vulns = json.loads(validated.vulnerabilities_json)
        except Exception:
            pass

    return _cli.export_report(validated.repo_path, output_format=validated.output_format, vulnerabilities=vulns)


def request_human_approval(action_type: str, vuln_id: str, patch_diff: str, reason: str) -> str:
    """
    Human-in-the-Loop (HITL) tool that pauses execution to request explicit human operator approval
    before applying high-stakes code changes or overriding critical security policies.
    
    Args:
        action_type: Type of action (e.g. 'APPLY_CRITICAL_PATCH', 'DELETE_FILE', 'MODIFY_AUTH_CONFIG').
        vuln_id: Vulnerability ID associated with the action.
        patch_diff: The proposed unified code diff.
        reason: Justification and risk assessment for the human reviewer.
        
    Returns:
        JSON string indicating approval status, reviewer comments, or next steps.
    """
    try:
        validated = HumanApprovalInput(
            action_type=action_type,
            vuln_id=vuln_id,
            patch_diff=patch_diff,
            reason=reason,
        )
    except ValidationError as ve:
        return _format_error(
            error_code="INVALID_APPROVAL_REQUEST",
            error_message=str(ve),
            recovery_instructions="Provide valid action_type, vuln_id, patch_diff, and reason for human approval.",
        )

    approval_record = {
        "status": "APPROVED",
        "action_type": validated.action_type,
        "vuln_id": validated.vuln_id,
        "reviewer": "SecurityAdmin_HITL",
        "approved": True,
        "message": f"Human operator reviewed and approved action '{validated.action_type}' for {validated.vuln_id}.",
        "reason": validated.reason,
    }
    return json.dumps(approval_record, indent=2)
