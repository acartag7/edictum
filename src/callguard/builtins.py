"""Built-in preconditions for common safety patterns."""

from __future__ import annotations

from collections.abc import Callable

from callguard.contracts import Verdict, precondition
from callguard.envelope import ToolEnvelope


def deny_sensitive_reads(
    sensitive_paths: list[str] | None = None,
    sensitive_commands: list[str] | None = None,
) -> Callable:
    """Built-in precondition: block reads of sensitive files/data.

    Default blocked paths:
    - ~/.ssh/
    - /var/run/secrets/ (k8s)
    - /.env, /.aws/credentials
    - /.git-credentials
    - /id_rsa, /id_ed25519

    Default blocked commands:
    - printenv, env (dump all env vars)
    """
    default_paths = [
        "/.ssh/",
        "/var/run/secrets/",
        "/.env",
        "/.aws/credentials",
        "/.git-credentials",
        "/id_rsa",
        "/id_ed25519",
    ]
    default_commands = ["printenv", "env"]

    paths = sensitive_paths or default_paths
    commands = sensitive_commands or default_commands

    @precondition("*")
    def _deny_sensitive(envelope: ToolEnvelope) -> Verdict:
        # Check file paths
        if envelope.file_path:
            for pattern in paths:
                if pattern in envelope.file_path:
                    return Verdict.fail(
                        f"Access to sensitive path blocked: {envelope.file_path}. "
                        "This file may contain secrets or credentials."
                    )

        # Check bash commands
        if envelope.bash_command:
            cmd = envelope.bash_command.strip()
            for blocked in commands:
                if cmd == blocked or cmd.startswith(blocked + " "):
                    return Verdict.fail(
                        f"Sensitive command blocked: {blocked}. "
                        "This command may expose secrets or environment variables."
                    )
            # Check if bash is reading a sensitive path
            for pattern in paths:
                if pattern in cmd:
                    return Verdict.fail(
                        f"Bash command accesses sensitive path: {pattern}. "
                        "This file may contain secrets or credentials."
                    )

        return Verdict.pass_()

    _deny_sensitive.__name__ = "deny_sensitive_reads"
    return _deny_sensitive
