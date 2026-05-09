import os
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.key_manager import (
    b64e,
    b64d,
    generate_x25519_keypair,
    public_key_to_b64,
    load_x25519_private_key,
    load_x25519_public_key,
    sign_data,
    verify_signature,
    verify_signed_prekey
)


MESSAGE_VERSION = 2
PROTOCOL_INFO = b"secure-instant-messaging-protocol-v2"


def canonical_json_bytes(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_symmetric_key(shared_secret: bytes, salt: bytes) -> bytes:
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=PROTOCOL_INFO
    ).derive(shared_secret)

    return key


def encrypt_message(plaintext: str, key: bytes, associated_data: bytes) -> dict:
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        associated_data
    )

    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext)
    }


def decrypt_message(ciphertext_b64: str, nonce_b64: str, key: bytes, associated_data: bytes) -> str:
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        b64d(nonce_b64),
        b64d(ciphertext_b64),
        associated_data
    )

    return plaintext.decode("utf-8")