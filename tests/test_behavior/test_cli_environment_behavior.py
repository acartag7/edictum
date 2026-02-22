"""Behavior tests for CLI --environment flag on test --cases and test --calls."""

from __future__ import annotations

import json
import tempfile

from click.testing import CliRunner

from edictum.cli.main import cli

# ---------------------------------------------------------------------------
# Fixtures: YAML bundle with environment-specific contract
# ---------------------------------------------------------------------------

ENV_BUNDLE = """\
apiVersion: edictum/v1
kind: ContractBundle

metadata:
  name: env-test-bundle

defaults:
  mode: enforce

contracts:
  - id: staging-only-deploy
    type: pre
    tool: deploy_service
    when:
      environment:
        equals: staging
    then:
      effect: deny
      message: "Deployments denied in staging."

  - id: block-prod-delete
    type: pre
    tool: delete_resource
    when:
      environment:
        not_equals: development
    then:
      effect: deny
      message: "Deletion only allowed in development."
"""


def _write(content: str, suffix: str = ".yaml") -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return f.name


class TestCliTestCasesEnvironment:
    """--environment flag on `edictum test --cases` changes evaluation."""

    def test_cases_environment_flag_affects_verdict(self):
        """A contract matching environment=staging should deny when --environment staging."""
        contracts = _write(ENV_BUNDLE)
        cases = _write(
            """\
cases:
  - id: deploy-staging-denied
    tool: deploy_service
    args:
      service: api
    expect: deny
    match_contract: staging-only-deploy
"""
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["test", contracts, "--cases", cases, "--environment", "staging"])
        assert result.exit_code == 0, f"Expected pass but got:\n{result.output}"
        assert "1/1 passed" in result.output

    def test_cases_default_environment_production(self):
        """Without --environment, default is production; staging-only contract should not fire."""
        contracts = _write(ENV_BUNDLE)
        cases = _write(
            """\
cases:
  - id: deploy-prod-allowed
    tool: deploy_service
    args:
      service: api
    expect: allow
"""
        )
        runner = CliRunner()
        # No --environment flag, defaults to production
        result = runner.invoke(cli, ["test", contracts, "--cases", cases])
        assert result.exit_code == 0, f"Expected pass but got:\n{result.output}"
        assert "1/1 passed" in result.output

    def test_cases_environment_development_allows_delete(self):
        """block-prod-delete denies unless environment=development."""
        contracts = _write(ENV_BUNDLE)
        cases = _write(
            """\
cases:
  - id: delete-dev-allowed
    tool: delete_resource
    args:
      resource: old-data
    expect: allow
"""
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["test", contracts, "--cases", cases, "--environment", "development"])
        assert result.exit_code == 0, f"Expected pass but got:\n{result.output}"
        assert "1/1 passed" in result.output

    def test_cases_per_case_environment_overrides_flag(self):
        """Per-case environment field should override the CLI flag."""
        contracts = _write(ENV_BUNDLE)
        cases = _write(
            """\
cases:
  - id: deploy-staging-denied
    tool: deploy_service
    args:
      service: api
    environment: staging
    expect: deny
    match_contract: staging-only-deploy
"""
        )
        runner = CliRunner()
        # CLI flag says production, but per-case says staging
        result = runner.invoke(cli, ["test", contracts, "--cases", cases, "--environment", "production"])
        assert result.exit_code == 0, f"Expected pass but got:\n{result.output}"
        assert "1/1 passed" in result.output


class TestCliTestCallsEnvironment:
    """--environment flag on `edictum test --calls` changes evaluation."""

    def test_calls_environment_flag_affects_verdict(self):
        """Calls evaluated with --environment staging should trigger staging-only contract."""
        contracts = _write(ENV_BUNDLE)
        calls = _write(
            json.dumps([{"tool": "deploy_service", "args": {"service": "api"}}]),
            suffix=".json",
        )
        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["test", contracts, "--calls", calls, "--json", "--environment", "staging"],
        )
        assert result.exit_code == 1  # denial
        parsed = json.loads(result.output)
        assert parsed[0]["verdict"] == "deny"

    def test_calls_default_environment_production(self):
        """Without --environment, staging-only contract should not fire."""
        contracts = _write(ENV_BUNDLE)
        calls = _write(
            json.dumps([{"tool": "deploy_service", "args": {"service": "api"}}]),
            suffix=".json",
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["test", contracts, "--calls", calls, "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed[0]["verdict"] == "allow"

    def test_calls_per_call_environment_overrides_flag(self):
        """Per-call environment field should override the CLI flag."""
        contracts = _write(ENV_BUNDLE)
        calls = _write(
            json.dumps(
                [
                    {
                        "tool": "deploy_service",
                        "args": {"service": "api"},
                        "environment": "staging",
                    }
                ]
            ),
            suffix=".json",
        )
        runner = CliRunner()
        # CLI flag says production, but per-call says staging
        result = runner.invoke(
            cli,
            [
                "test",
                contracts,
                "--calls",
                calls,
                "--json",
                "--environment",
                "production",
            ],
        )
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed[0]["verdict"] == "deny"
