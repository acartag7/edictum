"""YAML Bundle Loader — parse, validate against JSON Schema, compute bundle hash."""

from __future__ import annotations

import hashlib
import importlib.resources as _resources
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import jsonschema
    import yaml
except ImportError as _exc:
    raise ImportError(
        "The YAML engine requires pyyaml and jsonschema. Install them with: pip install edictum[yaml]"
    ) from _exc

MAX_BUNDLE_SIZE = 1_048_576  # 1 MB

# Lazy-loaded schema singleton
_schema_cache: dict | None = None


def _get_schema() -> dict:
    """Load and cache the JSON Schema for validation."""
    global _schema_cache  # noqa: PLW0603
    if _schema_cache is None:
        import json

        schema_text = (
            _resources.files("edictum.yaml_engine").joinpath("edictum-v1.schema.json").read_text(encoding="utf-8")
        )
        _schema_cache = json.loads(schema_text)
    return _schema_cache


@dataclass(frozen=True)
class BundleHash:
    """SHA256 hash of raw YAML bytes, used as policy_version."""

    hex: str

    def __str__(self) -> str:
        return self.hex


def _compute_hash(raw_bytes: bytes) -> BundleHash:
    """Compute SHA256 hash of raw YAML bytes."""
    return BundleHash(hex=hashlib.sha256(raw_bytes).hexdigest())


def _validate_schema(data: dict) -> None:
    """Validate parsed YAML against the Edictum JSON Schema."""
    from edictum import EdictumConfigError

    schema = _get_schema()
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        raise EdictumConfigError(f"Schema validation failed: {e.message}") from e


def _validate_unique_ids(data: dict) -> None:
    """Ensure all contract IDs are unique within the bundle."""
    from edictum import EdictumConfigError

    ids: set[str] = set()
    for contract in data.get("contracts", []):
        contract_id = contract.get("id")
        if contract_id in ids:
            raise EdictumConfigError(f"Duplicate contract id: '{contract_id}'")
        ids.add(contract_id)


def _validate_regexes(data: dict) -> None:
    """Compile all regex patterns at load time to catch invalid patterns early."""

    for contract in data.get("contracts", []):
        when = contract.get("when")
        if when:
            _validate_expression_regexes(when)


def _validate_expression_regexes(expr: dict | Any) -> None:
    """Recursively validate regex patterns in expressions."""

    if not isinstance(expr, dict):
        return

    # Boolean nodes
    if "all" in expr:
        for sub in expr["all"]:
            _validate_expression_regexes(sub)
        return
    if "any" in expr:
        for sub in expr["any"]:
            _validate_expression_regexes(sub)
        return
    if "not" in expr:
        _validate_expression_regexes(expr["not"])
        return

    # Leaf node: selector -> operator
    for _selector, operator in expr.items():
        if not isinstance(operator, dict):
            continue
        if "matches" in operator:
            _try_compile_regex(operator["matches"])
        if "matches_any" in operator:
            for pattern in operator["matches_any"]:
                _try_compile_regex(pattern)


def _validate_pre_selectors(data: dict) -> None:
    """Reject output.text selectors in type: pre contracts (spec violation)."""
    from edictum import EdictumConfigError

    for contract in data.get("contracts", []):
        if contract.get("type") != "pre":
            continue
        when = contract.get("when")
        if when and _expression_has_selector(when, "output.text"):
            raise EdictumConfigError(
                f"Contract '{contract.get('id', '?')}': output.text selector is not available in type: pre contracts"
            )


def _expression_has_selector(expr: dict | Any, target: str) -> bool:
    """Check if an expression tree contains a specific selector."""
    if not isinstance(expr, dict):
        return False
    if "all" in expr:
        return any(_expression_has_selector(sub, target) for sub in expr["all"])
    if "any" in expr:
        return any(_expression_has_selector(sub, target) for sub in expr["any"])
    if "not" in expr:
        return _expression_has_selector(expr["not"], target)
    # Leaf node: check selector keys
    return target in expr


def _try_compile_regex(pattern: str) -> None:
    """Attempt to compile a regex pattern, raising EdictumConfigError on failure."""
    from edictum import EdictumConfigError

    try:
        re.compile(pattern)
    except re.error as e:
        raise EdictumConfigError(f"Invalid regex pattern '{pattern}': {e}") from e


def load_bundle(source: str | Path) -> tuple[dict, BundleHash]:
    """Load and validate a YAML contract bundle.

    Args:
        source: Path to a YAML file.

    Returns:
        Tuple of (parsed bundle dict, bundle hash).

    Raises:
        EdictumConfigError: If the YAML is invalid, fails schema validation,
            has duplicate contract IDs, or contains invalid regex patterns.
        FileNotFoundError: If the file does not exist.
    """
    from edictum import EdictumConfigError

    path = Path(source)

    file_size = path.stat().st_size
    if file_size > MAX_BUNDLE_SIZE:
        raise EdictumConfigError(f"Bundle file too large ({file_size} bytes, max {MAX_BUNDLE_SIZE})")

    raw_bytes = path.read_bytes()
    bundle_hash = _compute_hash(raw_bytes)

    try:
        data = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as e:
        raise EdictumConfigError(f"YAML parse error: {e}") from e

    if not isinstance(data, dict):
        raise EdictumConfigError("YAML document must be a mapping")

    _validate_schema(data)
    _validate_unique_ids(data)
    _validate_regexes(data)
    _validate_pre_selectors(data)

    return data, bundle_hash


def load_bundle_string(content: str | bytes) -> tuple[dict, BundleHash]:
    """Load and validate a YAML contract bundle from a string or bytes.

    Like :func:`load_bundle` but accepts YAML content directly instead of
    a file path. Useful when YAML is generated programmatically or fetched
    from an API.

    Args:
        content: YAML content as a string or bytes.

    Returns:
        Tuple of (parsed bundle dict, bundle hash).

    Raises:
        EdictumConfigError: If the YAML is invalid, fails schema validation,
            has duplicate contract IDs, or contains invalid regex patterns.
    """
    from edictum import EdictumConfigError

    if isinstance(content, str):
        raw_bytes = content.encode("utf-8")
    else:
        raw_bytes = content

    if len(raw_bytes) > MAX_BUNDLE_SIZE:
        raise EdictumConfigError(f"Bundle content too large ({len(raw_bytes)} bytes, max {MAX_BUNDLE_SIZE})")

    bundle_hash = _compute_hash(raw_bytes)

    try:
        data = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as e:
        raise EdictumConfigError(f"YAML parse error: {e}") from e

    if not isinstance(data, dict):
        raise EdictumConfigError("YAML document must be a mapping")

    _validate_schema(data)
    _validate_unique_ids(data)
    _validate_regexes(data)
    _validate_pre_selectors(data)

    return data, bundle_hash
