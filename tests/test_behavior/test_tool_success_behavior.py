"""Behavior tests for case-insensitive _check_tool_success default heuristic.

All 8 adapters now use [:7].lower() before prefix checking. This file
verifies all case variants are handled correctly across all adapters.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum import Edictum
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_guard(**kwargs):
    defaults = {"environment": "test", "audit_sink": NullAuditSink(), "backend": MemoryBackend()}
    defaults.update(kwargs)
    return Edictum(**defaults)


def _tool_success_configs():
    """Return (name, adapter) tuples for all 8 adapters."""
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.google_adk import GoogleADKAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.nanobot import GovernedToolRegistry
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    guard = _make_guard()
    inner_mock = MagicMock()

    return [
        ("OpenAI", OpenAIAgentsAdapter(guard)),
        ("Agno", AgnoAdapter(guard)),
        ("SK", SemanticKernelAdapter(guard)),
        ("ClaudeSDK", ClaudeAgentSDKAdapter(guard)),
        ("CrewAI", CrewAIAdapter(guard)),
        ("LangChain", LangChainAdapter(guard)),
        ("Nanobot", GovernedToolRegistry(inner_mock, guard)),
        ("GoogleADK", GoogleADKAdapter(guard)),
    ]


CASE_VARIANTS = [
    ("Error: not found", False),
    ("error: timeout", False),
    ("ERROR: BOOM", False),
    ("eRrOr: mixed", False),
    ("fatal: crash", False),
    ("Fatal: oom", False),
    ("FATAL: disk full", False),
    ("fAtAl: mixed", False),
    ("Success", True),
    ("errorless result", True),
    ("fatality report", True),
    ("", True),
]

ADAPTER_CONFIGS = _tool_success_configs()
ADAPTER_IDS = [c[0] for c in ADAPTER_CONFIGS]


@pytest.mark.parametrize("response,expected", CASE_VARIANTS)
@pytest.mark.parametrize("name,adapter", ADAPTER_CONFIGS, ids=ADAPTER_IDS)
def test_case_insensitive_tool_success(name, adapter, response, expected):
    """_check_tool_success handles case variants of Error:/Fatal: prefixes."""
    result = adapter._check_tool_success("TestTool", response)
    assert result == expected, f"{name}: _check_tool_success({response!r}) = {result}, expected {expected}"


@pytest.mark.parametrize("name,adapter", ADAPTER_CONFIGS, ids=ADAPTER_IDS)
def test_none_response_is_success(name, adapter):
    """None tool response is treated as success."""
    assert adapter._check_tool_success("TestTool", None) is True


@pytest.mark.parametrize(
    "name,adapter",
    [c for c in ADAPTER_CONFIGS if c[0] != "Nanobot"],
    ids=[c[0] for c in ADAPTER_CONFIGS if c[0] != "Nanobot"],
)
def test_dict_is_error_detected(name, adapter):
    """dict with is_error=True is detected as failure."""
    assert adapter._check_tool_success("TestTool", {"is_error": True}) is False


def test_langchain_content_case_insensitive():
    """LangChain ToolMessage content check is case-insensitive."""
    from edictum.adapters.langchain import LangChainAdapter

    guard = _make_guard()
    adapter = LangChainAdapter(guard)

    msg = MagicMock()
    msg.content = "ERROR: something failed"
    assert adapter._check_tool_success("TestTool", msg) is False

    msg2 = MagicMock()
    msg2.content = "error: lower case"
    assert adapter._check_tool_success("TestTool", msg2) is False

    msg3 = MagicMock()
    msg3.content = "All good"
    assert adapter._check_tool_success("TestTool", msg3) is True


def test_custom_success_check_overrides_default():
    """Custom success_check bypasses the default string prefix logic."""
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter

    guard = _make_guard(success_check=lambda name, result: True)
    adapter = OpenAIAgentsAdapter(guard)

    assert adapter._check_tool_success("TestTool", "Error: something") is True
    assert adapter._check_tool_success("TestTool", "fatal: crash") is True


def test_sk_function_result_error_metadata():
    """SK adapter detects error in FunctionResult metadata."""
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    guard = _make_guard()
    adapter = SemanticKernelAdapter(guard)

    result = MagicMock()
    result.metadata = {"error": "something went wrong"}
    assert adapter._check_tool_success("TestTool", result) is False


def test_adk_dict_error_detected():
    """ADK adapter detects error key in dict responses."""
    from edictum.adapters.google_adk import GoogleADKAdapter

    guard = _make_guard()
    adapter = GoogleADKAdapter(guard)

    assert adapter._check_tool_success("TestTool", {"error": "failed"}) is False
    assert adapter._check_tool_success("TestTool", {"result": "ok"}) is True
