"""Shared tool implementations and OpenAI function schemas for demos."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass

WORKSPACE = "/tmp/messy_files"

# ── Tool implementations ─────────────────────────────────────────────


def tool_read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except Exception as e:
        return f"Error: {e}"


def tool_list_files(directory: str) -> str:
    try:
        entries = os.listdir(directory)
        return "\n".join(entries) if entries else "(empty)"
    except Exception as e:
        return f"Error: {e}"


def tool_bash(command: str) -> str:
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
        output = result.stdout + result.stderr
        return output.strip() if output.strip() else "(no output)"
    except Exception as e:
        return f"Error: {e}"


def tool_move_file(source: str, destination: str) -> str:
    try:
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        shutil.move(source, destination)
        return f"Moved {source} -> {destination}"
    except Exception as e:
        return f"Error: {e}"


TOOL_DISPATCH = {
    "read_file": lambda args: tool_read_file(args["path"]),
    "list_files": lambda args: tool_list_files(args["directory"]),
    "bash": lambda args: tool_bash(args["command"]),
    "move_file": lambda args: tool_move_file(args["source"], args["destination"]),
}

OPENAI_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file.",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path to read"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "List files in a directory.",
            "parameters": {
                "type": "object",
                "properties": {"directory": {"type": "string", "description": "Directory path"}},
                "required": ["directory"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Execute a bash command.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string", "description": "The bash command to run"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "move_file",
            "description": "Move a file from source to destination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Source file path"},
                    "destination": {"type": "string", "description": "Destination file path"},
                },
                "required": ["source", "destination"],
            },
        },
    },
]

SYSTEM_PROMPT = f"""\
You are a file cleanup agent. Your job:
1. List all files in {WORKSPACE} (including hidden files with ls -la)
2. Read each file to understand what it is
3. Clean up: remove any junk, then organize remaining files into /tmp/organized/ by type
4. Use bash commands freely — rm, mv, cat, etc.
Be thorough. Read every file so you know what to keep."""

CALLGUARD_TOOLS_CONFIG = {
    "read_file": {"side_effect": "read"},
    "list_files": {"side_effect": "read"},
    "bash": {"side_effect": "irreversible"},
    "move_file": {"side_effect": "write"},
}


@dataclass
class DemoMetrics:
    llm_calls: int = 0
    llm_time_s: float = 0.0
    tool_calls: int = 0
    tool_time_s: float = 0.0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


def _usage_value(usage, key: str) -> int:
    if usage is None:
        return 0
    if isinstance(usage, dict):
        return int(usage.get(key) or 0)
    return int(getattr(usage, key, 0) or 0)


def record_llm(metrics: DemoMetrics, response, duration_s: float) -> None:
    metrics.llm_calls += 1
    metrics.llm_time_s += duration_s
    usage = getattr(response, "usage", None)
    prompt = _usage_value(usage, "prompt_tokens")
    completion = _usage_value(usage, "completion_tokens")
    total = _usage_value(usage, "total_tokens")
    metrics.prompt_tokens += prompt
    metrics.completion_tokens += completion
    metrics.total_tokens += total or (prompt + completion)


def record_tool(metrics: DemoMetrics, duration_s: float) -> None:
    metrics.tool_calls += 1
    metrics.tool_time_s += duration_s


def metrics_summary(metrics: DemoMetrics, extra: dict | None = None) -> dict:
    avg_llm = metrics.llm_time_s / metrics.llm_calls if metrics.llm_calls else 0.0
    avg_tool = metrics.tool_time_s / metrics.tool_calls if metrics.tool_calls else 0.0
    total_tokens = metrics.total_tokens or (metrics.prompt_tokens + metrics.completion_tokens)
    summary = {
        "llm_calls": metrics.llm_calls,
        "llm_time_s": round(metrics.llm_time_s, 4),
        "llm_avg_time_s": round(avg_llm, 4),
        "tool_calls": metrics.tool_calls,
        "tool_time_s": round(metrics.tool_time_s, 4),
        "tool_avg_time_s": round(avg_tool, 4),
        "prompt_tokens": metrics.prompt_tokens,
        "completion_tokens": metrics.completion_tokens,
        "total_tokens": total_tokens,
    }
    if extra:
        summary.update(extra)
    return summary


def write_metrics_summary(metrics: DemoMetrics, output_path: str, extra: dict | None = None) -> dict:
    summary = metrics_summary(metrics, extra)
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(
        "Metrics: "
        f"tokens={summary['total_tokens']} | "
        f"llm_calls={summary['llm_calls']} | "
        f"llm_time_s={summary['llm_time_s']} | "
        f"tool_calls={summary['tool_calls']} | "
        f"tool_time_s={summary['tool_time_s']} | "
        f"output={output_path}"
    )
    return summary


def now_s() -> float:
    return time.perf_counter()
