"""Tests for Verdict and contract decorators."""

from __future__ import annotations

from callguard.contracts import Verdict, postcondition, precondition, session_contract


class TestVerdict:
    def test_pass(self):
        v = Verdict.pass_()
        assert v.passed is True
        assert v.message is None
        assert v.metadata == {}

    def test_fail(self):
        v = Verdict.fail("something went wrong")
        assert v.passed is False
        assert v.message == "something went wrong"

    def test_fail_truncation(self):
        long_msg = "x" * 600
        v = Verdict.fail(long_msg)
        assert len(v.message) == 500
        assert v.message.endswith("...")

    def test_fail_exact_500(self):
        msg = "x" * 500
        v = Verdict.fail(msg)
        assert v.message == msg

    def test_fail_with_metadata(self):
        v = Verdict.fail("err", key1="val1", key2=42)
        assert v.metadata == {"key1": "val1", "key2": 42}


class TestPrecondition:
    def test_decorator_sets_attributes(self):
        @precondition("Bash")
        def my_check(envelope):
            return Verdict.pass_()

        assert my_check._callguard_type == "precondition"
        assert my_check._callguard_tool == "Bash"
        assert my_check._callguard_when is None

    def test_decorator_with_when(self):
        def when_fn(e):
            return e.tool_name == "Bash"

        @precondition("Bash", when=when_fn)
        def my_check(envelope):
            return Verdict.pass_()

        assert my_check._callguard_when is when_fn

    def test_wildcard_tool(self):
        @precondition("*")
        def check_all(envelope):
            return Verdict.pass_()

        assert check_all._callguard_tool == "*"


class TestPostcondition:
    def test_decorator_sets_attributes(self):
        @postcondition("Write")
        def verify_output(envelope, result):
            return Verdict.pass_()

        assert verify_output._callguard_type == "postcondition"
        assert verify_output._callguard_tool == "Write"


class TestSessionContract:
    def test_decorator_sets_attributes(self):
        @session_contract
        async def max_ops(session):
            return Verdict.pass_()

        assert max_ops._callguard_type == "session_contract"
