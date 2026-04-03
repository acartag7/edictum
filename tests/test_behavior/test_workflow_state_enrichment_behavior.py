"""Behavior tests for enriched workflow state persistence and reset events."""

from __future__ import annotations

import json

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import (
    BlockedAction,
    PendingApproval,
    WorkflowRuntime,
    WorkflowState,
    load_workflow_string,
)
from edictum.workflow.state import load_state, save_state, workflow_state_key

_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: enrichment-test
stages:
  - id: stage-a
    tools: [Read]
  - id: stage-b
    tools: [Edit]
"""


def _make_session(session_id: str = "test-session") -> tuple[Session, MemoryBackend]:
    backend = MemoryBackend()
    return Session(session_id, backend), backend


def _make_definition():
    return load_workflow_string(_WORKFLOW)


class TestBlockedActionType:
    """BlockedAction dataclass has the expected fields."""

    def test_defaults(self):
        ba = BlockedAction()
        assert ba.tool == ""
        assert ba.summary == ""
        assert ba.message == ""
        assert ba.timestamp == ""

    def test_fields(self):
        ba = BlockedAction(
            tool="Bash",
            summary="git push origin main",
            message="Push to main not allowed",
            timestamp="2026-04-03T09:00:00Z",
        )
        assert ba.tool == "Bash"
        assert ba.summary == "git push origin main"
        assert ba.message == "Push to main not allowed"
        assert ba.timestamp == "2026-04-03T09:00:00Z"


class TestPendingApprovalType:
    """PendingApproval dataclass has the expected fields."""

    def test_defaults(self):
        pa = PendingApproval()
        assert pa.required is False
        assert pa.stage_id == ""
        assert pa.message == ""

    def test_fields(self):
        pa = PendingApproval(
            required=True,
            stage_id="review",
            message="Approve the review stage",
        )
        assert pa.required is True
        assert pa.stage_id == "review"
        assert pa.message == "Approve the review stage"


class TestWorkflowStateEnrichedFields:
    """WorkflowState carries enriched snapshot fields."""

    def test_defaults_are_none(self):
        state = WorkflowState()
        assert state.blocked_reason is None
        assert state.pending_approval is None
        assert state.last_blocked_action is None

    def test_fields_set(self):
        state = WorkflowState(
            blocked_reason="Tool not allowed",
            pending_approval=PendingApproval(required=True, stage_id="review", message="Approve"),
            last_blocked_action=BlockedAction(tool="Bash", summary="rm -rf /", message="Dangerous", timestamp="t"),
        )
        assert state.blocked_reason == "Tool not allowed"
        assert state.pending_approval.required is True
        assert state.pending_approval.stage_id == "review"
        assert state.last_blocked_action.tool == "Bash"
        assert state.last_blocked_action.summary == "rm -rf /"


class TestEnrichedStatePersistence:
    """Enriched fields round-trip through save/load."""

    async def test_round_trip_with_enriched_fields(self):
        session, backend = _make_session()
        definition = _make_definition()

        state = WorkflowState(
            session_id="test-session",
            active_stage="stage-a",
            blocked_reason="Tool blocked in stage",
            pending_approval=PendingApproval(
                required=True,
                stage_id="stage-a",
                message="Need approval for stage-a",
            ),
            last_blocked_action=BlockedAction(
                tool="Bash",
                summary="git push",
                message="Push not allowed",
                timestamp="2026-04-03T10:00:00Z",
            ),
        )
        state.ensure_defaults()
        await save_state(session, definition, state)

        loaded = await load_state(session, definition)
        assert loaded.blocked_reason == "Tool blocked in stage"
        assert loaded.pending_approval is not None
        assert loaded.pending_approval.required is True
        assert loaded.pending_approval.stage_id == "stage-a"
        assert loaded.pending_approval.message == "Need approval for stage-a"
        assert loaded.last_blocked_action is not None
        assert loaded.last_blocked_action.tool == "Bash"
        assert loaded.last_blocked_action.summary == "git push"
        assert loaded.last_blocked_action.message == "Push not allowed"
        assert loaded.last_blocked_action.timestamp == "2026-04-03T10:00:00Z"

    async def test_round_trip_with_none_enriched_fields(self):
        session, backend = _make_session()
        definition = _make_definition()

        state = WorkflowState(
            session_id="test-session",
            active_stage="stage-a",
        )
        state.ensure_defaults()
        await save_state(session, definition, state)

        loaded = await load_state(session, definition)
        assert loaded.blocked_reason is None
        assert loaded.pending_approval is None
        assert loaded.last_blocked_action is None

    async def test_serialized_json_contains_enriched_fields(self):
        session, backend = _make_session()
        definition = _make_definition()

        state = WorkflowState(
            session_id="test-session",
            active_stage="stage-a",
            blocked_reason="Blocked!",
            pending_approval=PendingApproval(required=True, stage_id="s1", message="m"),
            last_blocked_action=BlockedAction(tool="T", summary="s", message="m", timestamp="t"),
        )
        state.ensure_defaults()
        await save_state(session, definition, state)

        raw = await session.get_value(workflow_state_key(definition.metadata.name))
        assert raw is not None
        data = json.loads(raw)
        assert data["blocked_reason"] == "Blocked!"
        assert data["pending_approval"]["required"] is True
        assert data["pending_approval"]["stage_id"] == "s1"
        assert data["last_blocked_action"]["tool"] == "T"


class TestWorkflowResetEmitsStateUpdated:
    """WorkflowRuntime.reset() returns a workflow_state_updated event."""

    async def test_reset_returns_state_updated_event(self):
        runtime = WorkflowRuntime(load_workflow_string(_WORKFLOW))
        session, _ = _make_session()

        events = await runtime.reset(session, "stage-a")

        assert len(events) == 1
        event = events[0]
        assert event["action"] == "workflow_state_updated"
        assert event["workflow"]["workflow_name"] == "enrichment-test"
        assert event["workflow"]["stage_id"] == "stage-a"

    async def test_reset_clears_enriched_fields(self):
        runtime = WorkflowRuntime(load_workflow_string(_WORKFLOW))
        session, _ = _make_session()

        # Set up state with enriched fields
        state = await runtime.load_state(session)
        state.blocked_reason = "Previously blocked"
        state.pending_approval = PendingApproval(required=True, stage_id="stage-b", message="Waiting")
        state.last_blocked_action = BlockedAction(tool="Bash", summary="cmd", message="msg", timestamp="t")
        await runtime.save_state(session, state)

        # Reset
        await runtime.reset(session, "stage-a")

        # Verify enriched fields are cleared
        state = await runtime.load_state(session)
        assert state.active_stage == "stage-a"
        assert state.blocked_reason is None
        assert state.pending_approval is None
        assert state.last_blocked_action is None

    async def test_reset_to_second_stage(self):
        runtime = WorkflowRuntime(load_workflow_string(_WORKFLOW))
        session, _ = _make_session()

        events = await runtime.reset(session, "stage-b")
        assert events[0]["action"] == "workflow_state_updated"
        assert events[0]["workflow"]["stage_id"] == "stage-b"

        state = await runtime.load_state(session)
        assert state.active_stage == "stage-b"
        assert "stage-a" in state.completed_stages

    async def test_reset_invalid_stage_raises(self):
        runtime = WorkflowRuntime(load_workflow_string(_WORKFLOW))
        session, _ = _make_session()

        with pytest.raises(ValueError, match="unknown reset stage"):
            await runtime.reset(session, "nonexistent")
