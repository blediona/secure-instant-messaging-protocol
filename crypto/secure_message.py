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


def create_secure_message(
        sender_keys: dict,
        recipient_public_keys: dict,
        plaintext: str,
        sender_username: str,
        recipient_username: str
) -> dict:
    if not verify_signed_prekey(
      recipient_public_keys["signing_public_key"],
      recipient_public_keys["signed_prekey_public_key"],
      recipient_public_keys["signed_prekey_signature"],
    ):
        raise ValueError("Recipient signed pre-key is invalid.")

    ephemeral_private, ephemeral_public = generate_x25519_keypair()

    recipient_prekey_public=load_x25519_public_key(
        recipient_public_keys["signed_prekey_public_key"]
    )

    shared_secret = ephemeral_private.exchange(recipient_prekey_public)

    salt = os.urandom(16)

    symmetric_key = derive_symmetric_key(shared_secret, salt)

    ephemeral_public_key_b64 = public_key_to_b64(ephemeral_public)

    header = {
        "version": MESSAGE_VERSION,
        "algorithm": "X25519-HKDF-SHA256-AESGCM-Ed25519",
        "from": sender_username,
        "to": recipient_username,
        "sender_identity_public_key": sender_keys["identity_public_key"],
        "recipient_identity_public_key": recipient_public_keys["identity_public_key"],
        "recipient_signed_prekey_public_key": recipient_public_keys["signed_prekey_public_key"],
        "ephemeral_public_key": ephemeral_public_key_b64,
        "salt": b64e(salt)
    }

    associated_data = canonical_json_bytes(header)
    encrypted_data = encrypt_message(plaintext, symmetric_key, associated_data)

    signed_payload = {
        "header": header,
        "nonce": encrypted_data["nonce"],
        "ciphertext": encrypted_data["ciphertext"]
    }

    signature = sign_data(
        sender_keys["signing_private_key"],
        canonical_json_bytes(signed_payload)
    )

    return {
        "header": header,
        "nonce": encrypted_data["nonce"],
        "ciphertext": encrypted_data["ciphertext"],
        "signature": signature
    }

def open_secure_message(
        recipient_keys: dict,
        sender_public_keys: dict,
        secure_message: dict
) -> str:
    header = secure_message["header"]

    if header.get("recipient_identity_public_key") !=recipient_keys["identity_public_key"]:
        raise ValueError("This message was not encrypted for this recipient.")

    if header.get("sender_identity_public_key") != sender_public_keys["identity_public_key"]:
        raise ValueError("Sender identity key does not match the message header.")

    signed_payload = {
        "header": header,
        "nonce": secure_message["nonce"],
        "ciphertext": secure_message["ciphertext"]
    }

    is_valid = verify_signature(
        sender_public_keys["signing_public_key"],
        secure_message["signature"],
        canonical_json_bytes(signed_payload)
    )

    if not is_valid:
        raise ValueError("Invalid signature. Message may have been modified.")

    recipient_private_key = load_x25519_private_key(
        recipient_keys["signed_prekey_private_key"]
    )

    ephemeral_public_key = load_x25519_public_key(
        header["ephemeral_public_key"]
    )

    shared_secret = recipient_private_key.exchange(ephemeral_public_key)

    symmetric_key = derive_symmetric_key(
        shared_secret,
        b64d(header["salt"])
    )

    plaintext = decrypt_message(
        secure_message["ciphertext"],
        secure_message["nonce"],
        symmetric_key,
        canonical_json_bytes(header)
    )

    return plaintext