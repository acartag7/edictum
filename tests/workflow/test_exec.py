from __future__ import annotations

import pytest

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string
from edictum.workflow.result import WorkflowEvaluation

EXEC_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-verify
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("python3 -c \\"raise SystemExit(0)\\"", exit_code=0)
        message: command must pass
"""


def test_exec_evaluator_requires_opt_in():
    with pytest.raises(ValueError, match="exec\\(\\.\\.\\.\\) conditions require exec_evaluator_enabled=True"):
        WorkflowRuntime(load_workflow_string(EXEC_WORKFLOW))


@pytest.mark.asyncio
async def test_exec_evaluator_runs_when_enabled():
    runtime = WorkflowRuntime(load_workflow_string(EXEC_WORKFLOW), exec_evaluator_enabled=True)
    session = Session("exec-session", MemoryBackend())

    decision = await runtime.evaluate(session, create_envelope("Bash", {"command": "python3 -V"}))

    assert decision.action == "allow"
    await runtime.record_result(session, decision.stage_id, create_envelope("Bash", {"command": "python3 -V"}))
    state = await runtime.state(session)
    assert state.active_stage == ""


@pytest.mark.asyncio
async def test_exec_evaluator_times_out(monkeypatch):
    from edictum.workflow import evaluator_exec

    runtime = WorkflowRuntime(
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-timeout
stages:
  - id: wait-for-check
    exit:
      - condition: exec("python3 -c \\"import time; time.sleep(1)\\"", exit_code=0)
        message: command must finish
  - id: verify
    entry:
      - condition: stage_complete("wait-for-check")
    tools: [Bash]
"""
        ),
        exec_evaluator_enabled=True,
    )
    session = Session("exec-timeout", MemoryBackend())
    monkeypatch.setattr(evaluator_exec, "MAX_EXEC_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(ValueError, match="timed out"):
        await runtime.evaluate(session, create_envelope("Bash", {"command": "python3 -V"}))


@pytest.mark.asyncio
async def test_runtime_evaluation_stops_after_stage_iteration_limit(monkeypatch):
    runtime = WorkflowRuntime(
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: iteration-limit
stages:
  - id: review
    tools: [Read]
"""
        )
    )
    session = Session("iteration-limit", MemoryBackend())

    monkeypatch.setattr(
        runtime,
        "evaluate_current_stage",
        lambda stage, envelope: (False, WorkflowEvaluation(), None),
    )

    async def _complete(stage, state, envelope, has_next):
        return WorkflowEvaluation(), True

    monkeypatch.setattr(runtime, "evaluate_completion", _complete)
    monkeypatch.setattr(runtime, "next_index", lambda stage_id: (0, True))

    with pytest.raises(RuntimeError, match="stage iteration limit"):
        await runtime.evaluate(session, create_envelope("Read", {"path": "spec.md"}))
