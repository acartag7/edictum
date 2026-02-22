"""Behavior tests for the approval_backend parameter on Edictum.

Each test proves an observable effect of the approval_backend parameter:
- When None (default), no approval backend is stored
- When provided, it's stored and accessible
- from_yaml() and from_yaml_string() accept the parameter
"""

from __future__ import annotations

from edictum import Edictum
from edictum.approval import ApprovalBackend, LocalApprovalBackend
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

MINIMAL_YAML = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-bundle
defaults:
  mode: enforce
contracts:
  - id: noop
    type: pre
    tool: "__noop__"
    when:
      tool_name:
        equals: "__never_matches__"
    then:
      effect: deny
      message: "noop"
"""


def _make_guard(**overrides):
    defaults = dict(audit_sink=NullAuditSink(), backend=MemoryBackend())
    defaults.update(overrides)
    return Edictum(**defaults)


class TestApprovalBackendDefault:
    """Without approval_backend, the guard has no approval backend."""

    def test_default_is_none(self):
        guard = _make_guard()
        assert guard._approval_backend is None


class TestApprovalBackendProvided:
    """When approval_backend is provided, it's stored on the guard."""

    def test_stored_on_guard(self):
        backend = LocalApprovalBackend()
        guard = _make_guard(approval_backend=backend)
        assert guard._approval_backend is backend
        assert isinstance(guard._approval_backend, ApprovalBackend)


class TestApprovalBackendFromYaml:
    """from_yaml_string() passes approval_backend through to the constructor."""

    def test_from_yaml_string_with_backend(self, tmp_path):
        backend = LocalApprovalBackend()
        guard = Edictum.from_yaml_string(
            MINIMAL_YAML,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )
        assert guard._approval_backend is backend

    def test_from_yaml_string_without_backend(self):
        guard = Edictum.from_yaml_string(
            MINIMAL_YAML,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )
        assert guard._approval_backend is None


class TestApprovalBackendFromYamlFile:
    """from_yaml() passes approval_backend through to the constructor."""

    def test_from_yaml_with_backend(self, tmp_path):
        yaml_file = tmp_path / "contracts.yaml"
        yaml_file.write_text(MINIMAL_YAML)

        backend = LocalApprovalBackend()
        guard = Edictum.from_yaml(
            yaml_file,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )
        assert guard._approval_backend is backend
