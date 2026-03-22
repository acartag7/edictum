"""Behavior tests for value-level secret detection on safe-listed keys.

Proves that safe-listed keys (max_tokens, sort_keys, etc.) bypass key-name
detection but SECRET_VALUE_PATTERNS still catch secret values through
redact_args recursion — defense-in-depth against accidental credential leaks.
"""

from __future__ import annotations

import pytest

from edictum.audit import RedactionPolicy


@pytest.mark.security
class TestSafeListedKeysValueDetection:
    """Safe-listed keys bypass key-name detection but value-level detection still applies."""

    def test_safe_key_with_openai_key_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"max_tokens": "sk-reallyLongSecretKeyForTesting123"})
        assert result["max_tokens"] == "[REDACTED]"

    def test_safe_key_with_aws_key_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"num_tokens": "AKIAIOSFODNN7EXAMPLE"})
        assert result["num_tokens"] == "[REDACTED]"

    def test_safe_key_with_jwt_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"output_tokens": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"})
        assert result["output_tokens"] == "[REDACTED]"

    def test_safe_key_with_github_token_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"sort_keys": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"})
        assert result["sort_keys"] == "[REDACTED]"

    def test_safe_key_with_slack_token_still_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"index_keys": "xoxb-1234567890-abcdefghij"})
        assert result["index_keys"] == "[REDACTED]"

    def test_safe_key_with_numeric_value_not_redacted(self):
        """Normal numeric values on safe-listed keys are not redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == 1024

    def test_safe_key_with_normal_string_not_redacted(self):
        """Normal string values on safe-listed keys are not redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"sort_keys": "name,date"})
        assert result["sort_keys"] == "name,date"


@pytest.mark.security
class TestCustomSensitiveKeysOverrideSafeList:
    """User-supplied sensitive_keys must take precedence over _SAFE_COMPOUND_KEYS."""

    def test_custom_sensitive_key_overrides_safe_list(self):
        """sensitive_keys={"max_tokens"} must redact even though max_tokens is safe-listed."""
        policy = RedactionPolicy(sensitive_keys={"max_tokens"})
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == "[REDACTED]"

    def test_other_safe_keys_unaffected_by_custom_override(self):
        """Overriding one safe key must not affect other safe-listed keys."""
        policy = RedactionPolicy(sensitive_keys={"max_tokens"})
        result = policy.redact_args({"sort_keys": True})
        assert result["sort_keys"] is True

    def test_hyphen_sensitive_key_overrides_underscore_safe_key(self):
        """sensitive_keys={'max-tokens'} must redact max_tokens despite safe-list."""
        policy = RedactionPolicy(sensitive_keys={"max-tokens"})
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == "[REDACTED]"

    def test_underscore_sensitive_key_redacts_hyphen_arg(self):
        """sensitive_keys={'api_key'} must redact 'api-key' argument."""
        policy = RedactionPolicy(sensitive_keys={"api_key"})
        result = policy.redact_args({"api-key": "secret"})
        assert result["api-key"] == "[REDACTED]"


class TestCustomSafeCompoundKeys:
    """User-supplied safe_compound_keys extends the built-in safe list."""

    def test_custom_safe_key_prevents_redaction(self):
        """safe_compound_keys={"response_tokens"} must not redact despite 'tokens' word part."""
        policy = RedactionPolicy(safe_compound_keys={"response_tokens"})
        result = policy.redact_args({"response_tokens": 512})
        assert result["response_tokens"] == 512

    def test_custom_safe_key_with_hyphens(self):
        """Hyphenated form must also be recognized as safe."""
        policy = RedactionPolicy(safe_compound_keys={"context-tokens"})
        result = policy.redact_args({"context-tokens": 100})
        assert result["context-tokens"] == 100

    def test_custom_safe_key_does_not_affect_builtin_sensitive(self):
        """Adding safe keys must not suppress exact-match sensitive keys."""
        policy = RedactionPolicy(safe_compound_keys={"response_tokens"})
        result = policy.redact_args({"token": "abc123"})
        assert result["token"] == "[REDACTED]"

    def test_builtin_safe_keys_still_work_with_custom(self):
        """Built-in safe keys are preserved when custom ones are added."""
        policy = RedactionPolicy(safe_compound_keys={"response_tokens"})
        result = policy.redact_args({"max_tokens": 1024})
        assert result["max_tokens"] == 1024

    def test_without_custom_safe_key_would_redact(self):
        """Verify that without safe_compound_keys, the key IS redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"response_tokens": 512})
        assert result["response_tokens"] == "[REDACTED]"
