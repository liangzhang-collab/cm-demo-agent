"""
Automated Evaluation Suite for CodeMender Agent Regressions.
Evaluates agent performance against the golden benchmark dataset.
"""

import json
import os
import time
from typing import Any, Dict, List
from codemender_agent.tools.cli_wrapper import CodeMenderCLIWrapper


class AgentEvaluationSuite:
    """
    Automated regression benchmark evaluator for CodeMender Agent.
    Calculates detection accuracy, fix verification pass rates, and regression metrics.
    """

    def __init__(self, golden_dataset_path: Optional[str] = None):
        if golden_dataset_path is None:
            base_dir = os.path.dirname(__file__)
            golden_dataset_path = os.path.join(base_dir, "golden_dataset.json")
        self.golden_dataset_path = golden_dataset_path
        self.golden_cases = self._load_golden_dataset()
        self.cli = CodeMenderCLIWrapper()

    def _load_golden_dataset(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.golden_dataset_path):
            return []
        with open(self.golden_dataset_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def run_regression_eval(self, repo_path: str = ".") -> Dict[str, Any]:
        """
        Executes full regression evaluation against golden dataset.
        Returns accuracy, fix pass rate, and regression gating summary.
        """
        start_time = time.time()
        sast_vulns = self.cli.scan_sast(repo_path)
        sca_vulns = self.cli.scan_sca(repo_path)
        all_detected = {v.get("vuln_id"): v for v in (sast_vulns + sca_vulns)}

        total_golden = len(self.golden_cases)
        detected_golden_count = 0
        fixes_verified_count = 0

        eval_details = []

        for case in self.golden_cases:
            vid = case["vuln_id"]
            detected = vid in all_detected

            if detected:
                detected_golden_count += 1
                # Test fix generation & verification
                fix_res = self.cli.generate_fix(repo_path, vid)
                ver_res = self.cli.verify_fix(repo_path, vid)
                verified = ver_res.get("verified", False)
                if verified:
                    fixes_verified_count += 1

                eval_details.append({
                    "vuln_id": vid,
                    "detected": True,
                    "verified": verified,
                    "status": "PASS" if verified else "FAIL_VERIFICATION",
                })
            else:
                eval_details.append({
                    "vuln_id": vid,
                    "detected": False,
                    "verified": False,
                    "status": "FAIL_DETECTION",
                })

        detection_rate = (detected_golden_count / total_golden * 100) if total_golden else 100.0
        fix_success_rate = (fixes_verified_count / total_golden * 100) if total_golden else 100.0
        elapsed_seconds = round(time.time() - start_time, 4)

        passed_gating = (detection_rate == 100.0) and (fix_success_rate == 100.0)

        return {
            "passed_gating": passed_gating,
            "total_golden_cases": total_golden,
            "detected_count": detected_golden_count,
            "detection_rate_pct": detection_rate,
            "fixes_verified_count": fixes_verified_count,
            "fix_success_rate_pct": fix_success_rate,
            "elapsed_seconds": elapsed_seconds,
            "case_results": eval_details,
        }
