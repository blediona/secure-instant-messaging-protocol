import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519


PROJECT_ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = PROJECT_ROOT / "keys"
SIGNED_PREKEY_CONTEXT = b"secure-im signed prekey v1\n"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))
