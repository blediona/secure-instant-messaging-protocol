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

def generate_x25519_keypair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_b64(public_key) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return b64e(raw)


def private_key_to_b64(private_key) -> str:
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    return b64e(raw)

def load_x25519_private_key(private_key_b64: str):
    return x25519.X25519PrivateKey.from_private_bytes(b64d(private_key_b64))


def load_x25519_public_key(public_key_b64: str):
    return x25519.X25519PublicKey.from_public_bytes(b64d(public_key_b64))


def load_ed25519_private_key(private_key_b64: str):
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(private_key_b64))


def load_ed25519_public_key(public_key_b64: str):
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(public_key_b64))

def create_user_keys(username: str) -> dict:
    identity_private, identity_public = generate_x25519_keypair()
    signing_private, signing_public = generate_ed25519_keypair()

    keys = {
        "username": username,
        "identity_private_key": private_key_to_b64(identity_private),
        "identity_public_key": public_key_to_b64(identity_public),
        "signing_private_key": private_key_to_b64(signing_private),
        "signing_public_key": public_key_to_b64(signing_public)
    }

    rotate_signed_prekey(keys)

    return keys


def rotate_signed_prekey(keys: dict) -> dict:
    prekey_private, prekey_public = generate_x25519_keypair()
    prekey_public_b64 = public_key_to_b64(prekey_public)

    keys["signed_prekey_private_key"] = private_key_to_b64(prekey_private)
    keys["signed_prekey_public_key"] = prekey_public_b64
    keys["signed_prekey_signature"] = sign_data(
        keys["signing_private_key"],
        SIGNED_PREKEY_CONTEXT + prekey_public_b64.encode("utf-8")
    )

    return keys

def verify_signed_prekey(signing_public_key_b64: str, prekey_public_key_b64: str, signature_b64: str) -> bool:
    return verify_signature(
        signing_public_key_b64,
        signature_b64,
        SIGNED_PREKEY_CONTEXT + prekey_public_key_b64.encode("utf-8")
    )


def save_user_keys(username: str, keys: dict):
    KEY_DIR.mkdir(exist_ok=True)

    path = KEY_DIR / f"{username}.json"

    with open(path, "w", encoding="utf-8") as file:
        json.dump(keys, file, indent=4)


def load_user_keys(username: str) -> dict:
    path = KEY_DIR / f"{username}.json"

    if not path.exists():
        raise FileNotFoundError("Keys do not exist for this user.")

    with open(path, "r", encoding="utf-8") as file:
        keys = json.load(file)

    if "signed_prekey_private_key" not in keys:
        rotate_signed_prekey(keys)
        save_user_keys(username, keys)

    return keys