"""
Unit tests for SecretManager tool.
"""

import pytest
from codemender_agent.cicd.secrets import SecretManager


def test_secret_manager_retrieval_and_masking():
    sm = SecretManager(project_id="codemender-test")
    gemini_key = sm.get_secret("GEMINI_API_KEY")
    assert gemini_key is not None
    assert "AIza" in gemini_key

    masked = sm.mask_secret(gemini_key)
    assert masked.startswith("AIz")
    assert masked.endswith("026")
    assert "..." in masked


def test_secret_manager_missing_key():
    sm = SecretManager(project_id="codemender-test")
    with pytest.raises(ValueError):
        sm.get_secret("NON_EXISTENT_KEY_9999")
