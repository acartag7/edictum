"""Ed25519 bundle signature verification.

Requires the ``edictum[verified]`` extra (PyNaCl).
"""

from __future__ import annotations

import base64
import logging

logger = logging.getLogger(__name__)


class BundleVerificationError(Exception):
    """Raised when a bundle signature is invalid or missing."""


def verify_bundle_signature(
    yaml_bytes: bytes,
    signature_b64: str,
    public_key_hex: str,
) -> None:
    """Verify an Ed25519 signature over raw YAML bytes.

    Args:
        yaml_bytes: The raw YAML bundle bytes that were signed.
        signature_b64: Base64-encoded Ed25519 signature.
        public_key_hex: Hex-encoded Ed25519 public key.

    Raises:
        BundleVerificationError: If signature is invalid or missing.
        ImportError: If PyNaCl is not installed.
    """
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError:
        raise ImportError(
            "Bundle signature verification requires PyNaCl. Install with: pip install 'edictum[verified]'"
        ) from None

    if not signature_b64:
        raise BundleVerificationError("Signature is empty")

    if not public_key_hex:
        raise BundleVerificationError("Public key is empty")

    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise BundleVerificationError(f"Invalid public key hex encoding: {exc}") from exc

    try:
        signature_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise BundleVerificationError(f"Invalid signature base64 encoding: {exc}") from exc

    try:
        verify_key = VerifyKey(public_key_bytes)
        verify_key.verify(yaml_bytes, signature_bytes)
    except BadSignatureError:
        raise BundleVerificationError("Bundle signature verification failed — the bundle may have been tampered with")
    except Exception as exc:
        raise BundleVerificationError(f"Signature verification error: {exc}") from exc

    logger.debug("Bundle signature verified successfully")
