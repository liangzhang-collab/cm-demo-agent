"""
Unit tests for automated agent regression evaluation suite and golden benchmarks.
"""

import pytest
from codemender_agent.cicd.eval_suite import AgentEvaluationSuite


def test_agent_regression_evaluation_suite():
    eval_suite = AgentEvaluationSuite()
    results = eval_suite.run_regression_eval(".")

    assert results["total_golden_cases"] >= 3
    assert results["detected_count"] >= 3
    assert results["detection_rate_pct"] == 100.0
    assert results["fix_success_rate_pct"] == 100.0
    assert results["passed_gating"] is True
