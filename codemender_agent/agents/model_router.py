"""
Strategic Model Routing for CodeMender ADK Agents.
Dynamically routes tasks between lightweight, fast models (Flash) and high-reasoning models (Pro).
"""

from enum import Enum
from typing import Optional
from codemender_agent.config import SeverityLevel


class ModelTier(str, Enum):
    FLASH = "gemini-2.5-flash"  # Low-latency, cost-effective for scanning, parsing, environment audits
    PRO = "gemini-2.5-pro"      # Advanced reasoning for deep SAST, complex patch synthesis, policy validation


class ModelRouter:
    """
    Evaluates task complexity, security severity, and agent role to route execution
    to the optimal LLM model tier.
    """

    @classmethod
    def select_model_for_task(cls, task_type: str, severity: Optional[SeverityLevel] = None) -> str:
        """
        Selects the optimal model for a given task.
        
        Args:
            task_type: Type of task (e.g., 'AUDIT', 'SCA', 'SAST_SCAN', 'PATCH_SYNTHESIS', 'ROOT_ORCHESTRATOR').
            severity: Optional severity level of the target vulnerability.
            
        Returns:
            Model name string (e.g., 'gemini-2.5-flash' or 'gemini-2.5-pro').
        """
        task_upper = task_type.upper()

        # High-stakes or deep reasoning tasks use Pro tier
        if task_upper in ("PATCH_SYNTHESIS", "REPAIR_LOOP", "ROOT_ORCHESTRATOR", "POLICY_VERIFICATION"):
            return ModelTier.PRO.value

        if severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            return ModelTier.PRO.value

        # Lightweight / high-throughput tasks use Flash tier
        return ModelTier.FLASH.value
