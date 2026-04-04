from __future__ import annotations

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowState
from edictum.workflow.state import save_state
from tests.workflow.conftest import make_envelope, make_runtime


@pytest.mark.asyncio
async def test_final_stage_without_boundary_stays_active_after_success():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-final-stage-open
stages:
  - id: review
    tools: [Read]
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""
    )
    session = Session("behavior-final-stage-open", MemoryBackend())
    state = WorkflowState(
        session_id="behavior-final-stage-open",
        active_stage="push",
        completed_stages=["review"],
    )
    state.ensure_defaults()
    await save_state(session, runtime.definition, state)

    envelope = make_envelope("Bash", {"command": "git push origin feature"})
    await runtime.record_result(session, "push", envelope)
    current = await runtime.state(session)

    assert current.active_stage == "push"
    assert current.completed_stages == ["review"]
    assert current.evidence.stage_calls == {"push": ["git push origin feature"]}
