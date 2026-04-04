from __future__ import annotations

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from tests.workflow.conftest import make_envelope, make_runtime


@pytest.mark.asyncio
async def test_workflow_metadata_version_changes_audit_snapshot():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-workflow-version
  version: "2026-04-04"
stages:
  - id: implement
    tools: [Edit]
"""
    )
    session = Session("behavior-workflow-version", MemoryBackend())

    decision = await runtime.evaluate(session, make_envelope("Edit", {"path": "src/app.py"}))

    assert decision.audit is not None
    assert decision.audit["version"] == "2026-04-04"
