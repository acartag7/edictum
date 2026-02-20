"""YAML Contract Pipeline — parse, validate, and compile YAML contract bundles.

Requires optional dependencies: ``pip install edictum[yaml]``
"""

from __future__ import annotations

from edictum.yaml_engine.compiler import CompiledBundle
from edictum.yaml_engine.composer import (
    ComposedBundle,
    CompositionOverride,
    CompositionReport,
    ShadowContract,
    compose_bundles,
)
from edictum.yaml_engine.loader import BundleHash


def load_bundle(source: str) -> tuple[dict, BundleHash]:
    """Load and validate a YAML contract bundle. See :func:`loader.load_bundle`."""
    from edictum.yaml_engine.loader import load_bundle as _load

    return _load(source)


def compile_contracts(bundle: dict) -> CompiledBundle:
    """Compile a parsed bundle into contract objects. See :func:`compiler.compile_contracts`."""
    from edictum.yaml_engine.compiler import compile_contracts as _compile

    return _compile(bundle)


__all__ = [
    "BundleHash",
    "CompiledBundle",
    "ComposedBundle",
    "CompositionOverride",
    "CompositionReport",
    "ShadowContract",
    "compile_contracts",
    "compose_bundles",
    "load_bundle",
]
