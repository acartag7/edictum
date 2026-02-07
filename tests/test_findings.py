"""Tests for postcondition findings interface."""

from __future__ import annotations

import pytest

from edictum.findings import Finding, PostCallResult, classify_finding


class TestFinding:
    def test_creation(self):
        f = Finding(
            type="pii_detected",
            contract_id="pii-in-output",
            field="output.text",
            message="SSN pattern found",
        )
        assert f.type == "pii_detected"
        assert f.contract_id == "pii-in-output"
        assert f.field == "output.text"
        assert f.message == "SSN pattern found"
        assert f.metadata == {}

    def test_frozen(self):
        f = Finding(type="pii", contract_id="x", field="y", message="z")
        with pytest.raises(AttributeError):
            f.type = "other"

    def test_with_metadata(self):
        f = Finding(
            type="pii_detected",
            contract_id="pii-check",
            field="output.text",
            message="SSN found",
            metadata={"pattern": r"\d{3}-\d{2}-\d{4}", "match_count": 2},
        )
        assert f.metadata["match_count"] == 2

    def test_equality(self):
        f1 = Finding(type="pii", contract_id="c1", field="output", message="m")
        f2 = Finding(type="pii", contract_id="c1", field="output", message="m")
        assert f1 == f2


class TestPostCallResult:
    def test_default_passed(self):
        r = PostCallResult(result="hello")
        assert r.postconditions_passed is True
        assert r.findings == []

    def test_with_findings(self):
        findings = [
            Finding(type="pii_detected", contract_id="c1", field="output", message="SSN"),
            Finding(type="secret_detected", contract_id="c2", field="output", message="API key"),
        ]
        r = PostCallResult(result="raw output", postconditions_passed=False, findings=findings)
        assert not r.postconditions_passed
        assert len(r.findings) == 2
        assert r.findings[0].type == "pii_detected"

    def test_result_preserved(self):
        obj = {"data": [1, 2, 3]}
        r = PostCallResult(result=obj)
        assert r.result is obj


class TestClassifyFinding:
    def test_pii(self):
        assert classify_finding("pii-in-output", "SSN detected") == "pii_detected"
        assert classify_finding("check-patient-data", "found patient ID") == "pii_detected"

    def test_secret(self):
        assert classify_finding("no-secrets", "API key in output") == "secret_detected"
        assert classify_finding("credential-check", "") == "secret_detected"

    def test_limit(self):
        assert classify_finding("session-limit", "max calls exceeded") == "limit_exceeded"

    def test_default(self):
        assert classify_finding("some-rule", "something happened") == "policy_violation"

    def test_case_insensitive(self):
        assert classify_finding("PII-Check", "Found SSN") == "pii_detected"
        assert classify_finding("SECRET-SCAN", "Token found") == "secret_detected"
