"""Server SDK for connecting agents to edictum-server.

Install with: pip install edictum[server]
"""

from __future__ import annotations


def __getattr__(name: str):
    _imports = {
        "EdictumServerClient": "edictum.server.client",
        "EdictumServerError": "edictum.server.client",
        "ServerApprovalBackend": "edictum.server.approval_backend",
        "ServerAuditSink": "edictum.server.audit_sink",
        "ServerBackend": "edictum.server.backend",
        "ServerContractSource": "edictum.server.contract_source",
    }
    if name in _imports:
        import importlib

        module = importlib.import_module(_imports[name])
        return getattr(module, name)
    raise AttributeError(f"module 'edictum.server' has no attribute {name!r}")


__all__ = [
    "EdictumServerClient",
    "EdictumServerError",
    "ServerApprovalBackend",
    "ServerAuditSink",
    "ServerBackend",
    "ServerContractSource",
]
