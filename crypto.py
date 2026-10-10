"""All cryptography lives here so it is easy to audit and to explain.

  * AES-256-GCM   encrypts every medical record at rest (authenticated: tampering is detected).
  * Envelope keys each patient has their own data key, wrapped by a master key.
  * Ed25519       each hospital signs the records it issues (proves origin + integrity).
  * HS256 JWT     signed, expiring tokens for sessions and for doctor share links.
  * scrypt        password hashing.  HMAC-SHA256 for the Tier-3 share PIN.
"""
import base64
import hashlib
import hmac
import json
import os

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def canonical(obj) -> bytes:
    """Deterministic JSON bytes: the same object always signs/hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


# ---- passwords -------------------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${b64e(salt)}${b64e(digest)}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=b64d(salt), n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, b64d(digest))
    except ValueError:
        return False


# ---- AES-256-GCM + envelope keys ---------------------------------------------------------
def seal(key: bytes, plaintext: bytes, aad: bytes) -> str:
    """Encrypt. `aad` binds the ciphertext to its context (e.g. patient + record id)."""
    nonce = os.urandom(12)
    return b64e(nonce + AESGCM(key).encrypt(nonce, plaintext, aad))


def unseal(key: bytes, blob: str, aad: bytes) -> bytes:
    raw = b64d(blob)
    return AESGCM(key).decrypt(raw[:12], raw[12:], aad)  # raises InvalidTag if altered


def new_data_key(patient_id: str):
    dek = AESGCM.generate_key(bit_length=256)
    return dek, seal(config.MASTER_KEY, dek, b"dek:" + patient_id.encode())


def open_data_key(wrapped: str, patient_id: str) -> bytes:
    return unseal(config.MASTER_KEY, wrapped, b"dek:" + patient_id.encode())


# ---- Ed25519 hospital signatures ----------------------------------------------------------
def new_signing_key(hospital_id: str):
    sk = Ed25519PrivateKey.generate()
    raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64e(pub), seal(config.MASTER_KEY, raw, b"sk:" + hospital_id.encode())


def sign(wrapped_key: str, hospital_id: str, message: bytes) -> str:
    raw = unseal(config.MASTER_KEY, wrapped_key, b"sk:" + hospital_id.encode())
    return b64e(Ed25519PrivateKey.from_private_bytes(raw).sign(message))


def verify(public_key: str, signature: str, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(b64d(public_key)).verify(b64d(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def fingerprint(public_key: str) -> str:
    return hashlib.sha256(b64d(public_key)).hexdigest()[:16]


# ---- JWT (sessions + share links) ---------------------------------------------------------
def sign_token(claims: dict) -> str:
    return jwt.encode(claims, config.SECRET_KEY, algorithm="HS256")


def read_token(token: str, typ: str) -> dict:
    """Verify signature + expiry and make sure a share token can't be used as a session."""
    claims = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"], options={"require": ["exp", "typ"]})
    if claims["typ"] != typ:
        raise jwt.InvalidTokenError("wrong token type")
    return claims


# ---- Tier-3 PIN -----------------------------------------------------------------------------
def pin_digest(share_id: str, pin: str) -> str:
    return hmac.new(config.SECRET_KEY.encode(), f"{share_id}:{pin}".encode(), hashlib.sha256).hexdigest()


def pin_matches(share_id: str, pin: str, stored: str) -> bool:
    return hmac.compare_digest(pin_digest(share_id, pin), stored)
