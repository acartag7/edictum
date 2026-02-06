"""Tests for built-in preconditions."""

from __future__ import annotations

from callguard.builtins import deny_sensitive_reads
from callguard.envelope import create_envelope


class TestDenySensitiveReads:
    def test_blocks_ssh_path(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "~/.ssh/id_rsa"})
        verdict = check(envelope)
        assert not verdict.passed
        assert "sensitive path" in verdict.message.lower()

    def test_blocks_expanded_ssh_path(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/home/user/.ssh/id_rsa"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_blocks_env_file(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/app/.env"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_blocks_aws_credentials(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/home/user/.aws/credentials"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_blocks_git_credentials(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/home/user/.git-credentials"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_blocks_k8s_secrets(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/var/run/secrets/kubernetes.io/token"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_allows_normal_file(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Read", {"file_path": "/app/src/main.py"})
        verdict = check(envelope)
        assert verdict.passed

    def test_blocks_printenv_command(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Bash", {"command": "printenv"})
        verdict = check(envelope)
        assert not verdict.passed
        assert "sensitive command" in verdict.message.lower()

    def test_blocks_env_command(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Bash", {"command": "env"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_blocks_env_with_args(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Bash", {"command": "env | grep AWS"})
        verdict = check(envelope)
        # This gets caught by the command check (starts with "env ")
        # OR by the fact that bash_command contains the env command
        assert not verdict.passed

    def test_allows_normal_command(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Bash", {"command": "ls -la"})
        verdict = check(envelope)
        assert verdict.passed

    def test_blocks_bash_reading_sensitive_path(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("Bash", {"command": "cat ~/.ssh/id_rsa"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_custom_paths(self):
        check = deny_sensitive_reads(sensitive_paths=["/custom/secret"])
        envelope = create_envelope("Read", {"file_path": "/custom/secret/data.txt"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_custom_commands(self):
        check = deny_sensitive_reads(sensitive_commands=["vault read"])
        envelope = create_envelope("Bash", {"command": "vault read secret/data"})
        verdict = check(envelope)
        assert not verdict.passed

    def test_custom_doesnt_block_defaults(self):
        check = deny_sensitive_reads(sensitive_paths=["/custom/only"])
        envelope = create_envelope("Read", {"file_path": "/app/.env"})
        verdict = check(envelope)
        # Custom paths replace defaults
        assert verdict.passed

    def test_has_correct_name(self):
        check = deny_sensitive_reads()
        assert check.__name__ == "deny_sensitive_reads"

    def test_has_precondition_attributes(self):
        check = deny_sensitive_reads()
        assert check._callguard_type == "precondition"
        assert check._callguard_tool == "*"

    def test_no_file_path_no_command_passes(self):
        check = deny_sensitive_reads()
        envelope = create_envelope("TestTool", {"key": "value"})
        verdict = check(envelope)
        assert verdict.passed
