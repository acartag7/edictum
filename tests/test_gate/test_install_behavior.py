"""Behavior tests for gate install/uninstall."""

from __future__ import annotations

import json
import os
from pathlib import Path

from edictum.gate.install import (
    install_claude_code,
    install_cline,
    install_opencode,
    uninstall_claude_code,
    uninstall_cline,
    uninstall_opencode,
)


class TestClaudeCodeInstall:
    def test_install_creates_settings(self, tmp_path: Path) -> None:
        result = install_claude_code(home=tmp_path)
        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1
        assert "edictum gate check" in hooks[0]["hooks"][0]["command"]
        assert "Installed" in result

    def test_install_merges_hooks(self, tmp_path: Path) -> None:
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        existing = {"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": "other-hook"}]}]}}
        (claude_dir / "settings.json").write_text(json.dumps(existing))

        install_claude_code(home=tmp_path)
        settings = json.loads((claude_dir / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 2  # existing + edictum

    def test_install_idempotent(self, tmp_path: Path) -> None:
        install_claude_code(home=tmp_path)
        result = install_claude_code(home=tmp_path)
        assert "already installed" in result

        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 1  # No duplicate

    def test_uninstall_removes_hook(self, tmp_path: Path) -> None:
        install_claude_code(home=tmp_path)
        uninstall_claude_code(home=tmp_path)
        settings = json.loads((tmp_path / ".claude" / "settings.json").read_text())
        hooks = settings["hooks"]["PreToolUse"]
        assert len(hooks) == 0

    def test_uninstall_missing_file(self, tmp_path: Path) -> None:
        result = uninstall_claude_code(home=tmp_path)
        assert "No Claude Code settings" in result


class TestClineInstall:
    def test_install_creates_script(self, tmp_path: Path) -> None:
        install_cline(home=tmp_path)
        script = tmp_path / "Documents" / "Cline" / "Rules" / "Hooks" / "edictum-gate.sh"
        assert script.exists()
        content = script.read_text()
        assert "edictum gate check --format cline" in content

    def test_install_executable(self, tmp_path: Path) -> None:
        install_cline(home=tmp_path)
        script = tmp_path / "Documents" / "Cline" / "Rules" / "Hooks" / "edictum-gate.sh"
        assert os.access(str(script), os.X_OK)

    def test_uninstall_removes_script(self, tmp_path: Path) -> None:
        install_cline(home=tmp_path)
        uninstall_cline(home=tmp_path)
        script = tmp_path / "Documents" / "Cline" / "Rules" / "Hooks" / "edictum-gate.sh"
        assert not script.exists()


class TestOpenCodeInstall:
    def test_install_creates_plugin(self, tmp_path: Path) -> None:
        install_opencode(home=tmp_path)
        plugin = tmp_path / ".opencode" / "plugins" / "edictum-gate.ts"
        assert plugin.exists()
        content = plugin.read_text()
        assert "edictum gate check" in content

    def test_uninstall_removes_plugin(self, tmp_path: Path) -> None:
        install_opencode(home=tmp_path)
        uninstall_opencode(home=tmp_path)
        plugin = tmp_path / ".opencode" / "plugins" / "edictum-gate.ts"
        assert not plugin.exists()
