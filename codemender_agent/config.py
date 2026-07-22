"""
Configuration schemas, Pydantic data models, and strict tool input schemas for CodeMender ADK Agent.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class VulnerabilityStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    IN_PROGRESS = "IN_PROGRESS"
    PATCH_GENERATED = "PATCH_GENERATED"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    FAILED = "FAILED"
    REJECTED_BY_POLICY = "REJECTED_BY_POLICY"
    PENDING_APPROVAL = "PENDING_APPROVAL"


class Vulnerability(BaseModel):
    vuln_id: str = Field(..., description="Unique vulnerability identifier (e.g., SAST-SQLI-001)")
    title: str = Field(..., description="Short summary of vulnerability")
    severity: SeverityLevel = Field(..., description="Vulnerability severity level")
    file_path: str = Field(..., description="File path relative to repository root")
    line_number: Optional[int] = Field(None, description="Affected line number if applicable")
    cve_id: Optional[str] = Field(None, description="Associated CVE ID or CWE ID if applicable")
    category: str = Field("SAST", description="Scan category: SAST or SCA")
    description: str = Field("", description="Detailed description and risk assessment")
    status: VulnerabilityStatus = Field(VulnerabilityStatus.DISCOVERED, description="Current remediation state")
    patch_diff: Optional[str] = Field(None, description="Unified patch diff if fix generated")


class ScanSummary(BaseModel):
    repo_path: str = Field(..., description="Target repository path")
    timestamp: str = Field(..., description="Scan execution timestamp")
    total_scanned_files: int = Field(0, description="Total files scanned")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="List of detected vulnerabilities")
    sast_count: int = Field(0, description="Total SAST vulnerabilities")
    sca_count: int = Field(0, description="Total SCA vulnerabilities")
    high_critical_count: int = Field(0, description="Count of High and Critical vulnerabilities")


class FixResult(BaseModel):
    vuln_id: str = Field(..., description="Vulnerability ID")
    patch_applied: bool = Field(False, description="Whether patch was applied to codebase")
    verified: bool = Field(False, description="Whether fix was verified clean")
    details: str = Field("", description="Verification test output or error logs")
    attempts: int = Field(1, description="Number of repair attempts")
    patch_diff: Optional[str] = Field(None, description="Unified patch diff")
    recovery_instructions: Optional[str] = Field(None, description="Actionable recovery instructions if failed")


class ScanConfig(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository")
    min_severity: SeverityLevel = Field(SeverityLevel.HIGH, description="Minimum severity threshold for CI gating")
    auto_apply_fixes: bool = Field(True, description="Whether to automatically apply verified fixes")
    max_repair_loops: int = Field(5, description="Maximum iterations for repair loop")


# =====================================================================
# Strict Tool Input Validation Schemas (Pydantic Models)
# =====================================================================

class CheckEnvInput(BaseModel):
    repo_path: str = Field(".", description="Path to local target repository directory")


class ScanSastInput(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository directory")
    min_severity: Optional[SeverityLevel] = Field(None, description="Optional minimum severity filter")


class ScanScaInput(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository directory")
    manifest_file: Optional[str] = Field(None, description="Specific manifest file (e.g. requirements.txt)")


class GenerateFixInput(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository directory")
    vuln_id: str = Field(..., description="Unique vulnerability ID to generate a patch for (e.g. SAST-SQLI-001)")
    context_lines: int = Field(3, ge=1, le=20, description="Number of context lines for patch diff generation")

    @field_validator("vuln_id")
    @classmethod
    def validate_vuln_id(cls, v: str) -> str:
        v_clean = v.strip()
        if not v_clean:
            raise ValueError("vuln_id must not be empty")
        return v_clean


class VerifyFixInput(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository directory")
    vuln_id: str = Field(..., description="Unique vulnerability ID to verify")
    sandbox_timeout: int = Field(60, ge=5, le=300, description="Verification sandbox timeout in seconds")


class ExportReportInput(BaseModel):
    repo_path: str = Field(".", description="Target repository path")
    vulnerabilities_json: Optional[str] = Field(None, description="Optional JSON string of vulnerability records")
    output_format: str = Field("markdown", description="Output format: 'markdown', 'html', or 'json'")


class HumanApprovalInput(BaseModel):
    action_type: str = Field(..., description="Type of high-stakes action (e.g. APPLY_CRITICAL_PATCH, DELETE_FILE)")
    vuln_id: str = Field(..., description="Target vulnerability ID")
    patch_diff: str = Field(..., description="Unified patch diff content proposed for application")
    reason: str = Field(..., description="Justification and impact analysis for human reviewer")


# =====================================================================
# Structured Tool Result & Error Models
# =====================================================================

class ToolErrorResponse(BaseModel):
    success: bool = Field(False, description="Always False for error responses")
    error_code: str = Field(..., description="Structured error code (e.g. INVALID_INPUT, CLI_NOT_FOUND, VULN_NOT_FOUND)")
    error_message: str = Field(..., description="Detailed description of what caused the failure")
    recovery_instructions: str = Field(..., description="Actionable step-by-step instructions for LLM to recover")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional debug context")


class ToolSuccessResponse(BaseModel):
    success: bool = Field(True, description="Always True for success responses")
    data: Any = Field(..., description="Returned data payload")
    message: str = Field("Operation completed successfully", description="Status message")
