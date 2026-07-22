"""
Configuration schemas and data models for CodeMender ADK Agent.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


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


class Vulnerability(BaseModel):
    vuln_id: str = Field(..., description="Unique vulnerability identifier (e.g., VULN-001)")
    title: str = Field(..., description="Short summary of vulnerability")
    severity: SeverityLevel = Field(..., description="Vulnerability severity level")
    file_path: str = Field(..., description="File path relative to repository root")
    line_number: Optional[int] = Field(None, description="Affected line number if applicable")
    cve_id: Optional[str] = Field(None, description="Associated CVE ID if applicable")
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


class ScanConfig(BaseModel):
    repo_path: str = Field(".", description="Path to target local repository")
    min_severity: SeverityLevel = Field(SeverityLevel.HIGH, description="Minimum severity threshold for CI gating")
    auto_apply_fixes: bool = Field(True, description="Whether to automatically apply verified fixes")
    max_repair_loops: int = Field(5, description="Maximum iterations for repair loop")
