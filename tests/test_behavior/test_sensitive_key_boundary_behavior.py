"""Behavior tests for _is_sensitive_key word-boundary matching.

Proves that whole-word matching prevents false positives on fields
like 'monkey' and 'hockey' while still catching 'api_key' and 'auth-token'.
"""

from __future__ import annotations

from edictum.audit import RedactionPolicy


class TestSensitiveKeyFalsePositives:
    """Words containing 'key' as a substring must NOT be redacted."""

    def test_monkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"monkey": "banana"})
        assert result["monkey"] == "banana"

    def test_hockey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"hockey": "puck"})
        assert result["hockey"] == "puck"

    def test_donkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"donkey": "shrek"})
        assert result["donkey"] == "shrek"

    def test_jockey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"jockey": "rider"})
        assert result["jockey"] == "rider"

    def test_turkey_not_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"turkey": "gobble"})
        assert result["turkey"] == "gobble"


class TestSensitiveKeyTruePositives:
    """Real sensitive keys must still be caught."""

    def test_api_key_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"api_key": "secret"})
        assert result["api_key"] == "[REDACTED]"

    def test_auth_token_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"auth-token": "secret"})
        assert result["auth-token"] == "[REDACTED]"

    def test_user_password_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"user_password": "secret"})
        assert result["user_password"] == "[REDACTED]"

    def test_client_secret_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"client_secret": "secret"})
        assert result["client_secret"] == "[REDACTED]"

    def test_access_credential_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"access-credential": "secret"})
        assert result["access-credential"] == "[REDACTED]"

    def test_exact_match_still_works(self):
        """Keys in DEFAULT_SENSITIVE_KEYS still match (e.g., 'apikey')."""
        policy = RedactionPolicy()
        result = policy.redact_args({"apikey": "secret"})
        assert result["apikey"] == "[REDACTED]"

    def test_bare_key_redacted(self):
        """The word 'key' alone should be redacted."""
        policy = RedactionPolicy()
        result = policy.redact_args({"key": "secret"})
        assert result["key"] == "[REDACTED]"


class TestSensitiveKeyPluralForms:
    """Plural forms of sensitive words must also be caught."""

    def test_user_credentials_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"user_credentials": "secret"})
        assert result["user_credentials"] == "[REDACTED]"

    def test_api_tokens_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"api_tokens": "secret"})
        assert result["api_tokens"] == "[REDACTED]"

    def test_db_passwords_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"db_passwords": "secret"})
        assert result["db_passwords"] == "[REDACTED]"

    def test_oauth_secrets_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"oauth_secrets": "secret"})
        assert result["oauth_secrets"] == "[REDACTED]"

    def test_encryption_keys_redacted(self):
        policy = RedactionPolicy()
        result = policy.redact_args({"encryption_keys": "secret"})
        assert result["encryption_keys"] == "[REDACTED]"
