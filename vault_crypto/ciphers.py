"""AES / DES / RC4 primitives and the password-based "envelope" used by the app.

Library choice: ``cryptography`` (pyca). It wraps OpenSSL, is actively maintained,
exposes every required mode (CBC/CFB/OFB/CTR/GCM) behind one API, and ships a
correct PKCS#7 implementation, so we do not hand-roll padding (the original
project's ``pkcs7unpad`` did not validate anything).

Two layers:
  * raw_encrypt / raw_decrypt  - bare cipher + mode (used by the benchmark so
    that timing measures exactly the cipher, nothing else).
  * encrypt_bytes / decrypt_bytes - password-based envelope used by the web app:
    PBKDF2 -> HKDF (separate encryption key and MAC key) -> cipher ->
    HMAC-SHA256 (encrypt-then-MAC) or AES-GCM's own tag.

DES and RC4 are obsolete and only present because the assignment requires them.
DES is implemented as TripleDES with an 8-byte key (K1=K2=K3), which is
mathematically identical to single DES (the cryptography library no longer
exposes single DES directly).
"""
from __future__ import annotations

import hmac
import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:  # cryptography >= 43 moved the legacy ciphers here
    from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4, TripleDES
except ImportError:  # pragma: no cover - older cryptography releases
    from cryptography.hazmat.primitives.ciphers.algorithms import ARC4, TripleDES  # type: ignore


class DecryptionError(Exception):
    """Wrong password, tampered/corrupted ciphertext, or invalid metadata.

    Deliberately one generic error: distinguishing "wrong password" from
    "tampered data" would only help an attacker.
    """


class UnsupportedAlgorithm(ValueError):
    pass


# name -> (family, key_len, iv_len, needs_padding, authenticated_by_itself)
ALGORITHMS = {
    "AES-GCM": dict(
        family="AES",
        mode="GCM",
        key_len=32,
        iv_len=12,
        padded=False,
        aead=True,
    ),
    "DES-CBC": dict(
        family="DES",
        mode="CBC",
        key_len=8,
        iv_len=8,
        padded=True,
        aead=False,
    ),
    "RC4": dict(
        family="RC4",
        mode="STREAM",
        key_len=32,
        iv_len=0,
        padded=False,
        aead=False,
    ),
}

REQUIRED_ALGORITHMS = ("AES-GCM", "DES-CBC", "RC4")
GCM_TAG_LEN = 16
MAC_LEN = 32


def _spec(algorithm: str) -> dict:
    try:
        return ALGORITHMS[algorithm]
    except KeyError:
        raise UnsupportedAlgorithm(f"Unsupported algorithm: {algorithm!r}") from None


def _cipher(algorithm: str, key: bytes, iv: bytes) -> Cipher:
    s = _spec(algorithm)
    if len(key) != s["key_len"] or len(iv) != s["iv_len"]:
        raise ValueError("Wrong key or IV length")
    if s["family"] == "AES":
        mode = {"CBC": modes.CBC, "CFB": modes.CFB, "OFB": modes.OFB, "CTR": modes.CTR}[s["mode"]](iv)
        return Cipher(algorithms.AES(key), mode)
    if s["family"] == "DES":
        return Cipher(TripleDES(key), modes.CBC(iv))
    return Cipher(ARC4(key), mode=None)


def raw_encrypt(algorithm: str, key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Encrypt ``data``; CBC modes apply PKCS#7, GCM appends its 16-byte tag."""
    s = _spec(algorithm)
    if s["aead"]:
        enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(aad)
        return enc.update(data) + enc.finalize() + enc.tag
    enc = _cipher(algorithm, key, iv).encryptor()
    if s["padded"]:
        bs = 16 if s["family"] == "AES" else 8
        padder = padding.PKCS7(bs * 8).padder()
        data = padder.update(data) + padder.finalize()
    return enc.update(data) + enc.finalize()


def raw_decrypt(algorithm: str, key: bytes, iv: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Inverse of raw_encrypt. Raises DecryptionError on bad padding / bad GCM tag."""
    s = _spec(algorithm)
    try:
        if s["aead"]:
            if len(data) < GCM_TAG_LEN:
                raise DecryptionError("ciphertext too short")
            body, tag = data[:-GCM_TAG_LEN], data[-GCM_TAG_LEN:]
            dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
            dec.authenticate_additional_data(aad)
            return dec.update(body) + dec.finalize()
        bs = 16 if s["family"] == "AES" else 8
        if s["padded"] and (len(data) == 0 or len(data) % bs):
            raise DecryptionError("ciphertext length is not a multiple of the block size")
        dec = _cipher(algorithm, key, iv).decryptor()
        out = dec.update(data) + dec.finalize()
        if s["padded"]:
            unp = padding.PKCS7(bs * 8).unpadder()
            out = unp.update(out) + unp.finalize()  # validates every padding byte
        return out
    except DecryptionError:
        raise
    except Exception as exc:  # InvalidTag, ValueError (bad padding), ...
        raise DecryptionError("decryption failed") from exc


# ---------------------------------------------------------------- envelope ---
def derive_keys(password: str, salt: bytes, iterations: int, algorithm: str) -> tuple[bytes, bytes]:
    """PBKDF2-HMAC-SHA256 -> master secret; HKDF-Expand gives *separate* keys.

    The encryption key and the MAC key must never be the same bytes, so each
    gets its own HKDF ``info`` label (which also binds the algorithm name).
    """
    master = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(password.encode("utf-8"))
    enc_len = _spec(algorithm)["key_len"]
    enc = HKDFExpand(hashes.SHA256(), enc_len, b"vault-enc|" + algorithm.encode()).derive(master)
    mac = HKDFExpand(hashes.SHA256(), 32, b"vault-mac|" + algorithm.encode()).derive(master)
    return enc, mac


def _header(algorithm: str, iterations: int, salt: bytes, iv: bytes) -> bytes:
    """Canonical, length-prefixed header: authenticated so parameters cannot be swapped."""
    a = algorithm.encode()
    return b"vault-v1" + struct.pack(">H", len(a)) + a + struct.pack(">Q", iterations) + \
        struct.pack(">H", len(salt)) + salt + struct.pack(">H", len(iv)) + iv


@dataclass
class Envelope:
    algorithm: str
    kdf_iterations: int
    salt: bytes
    iv: bytes
    ciphertext: bytes
    mac: bytes  # empty for AES-GCM (the GCM tag is inside ``ciphertext``)


def encrypt_bytes(data: bytes, password: str, algorithm: str, iterations: int = 600_000) -> Envelope:
    s = _spec(algorithm)
    salt = os.urandom(16)  # unique per file, public
    iv = os.urandom(s["iv_len"])  # unique per encryption, public
    enc_key, mac_key = derive_keys(password, salt, iterations, algorithm)
    header = _header(algorithm, iterations, salt, iv)
    ct = raw_encrypt(algorithm, enc_key, iv, data, aad=header)
    mac = b""
    if not s["aead"]:  # encrypt-then-MAC for CBC/CFB/OFB/CTR/DES/RC4
        h = hmac.new(mac_key, header + ct, "sha256")
        mac = h.digest()
    return Envelope(algorithm, iterations, salt, iv, ct, mac)


def decrypt_bytes(env: Envelope, password: str, max_iterations: int = 5_000_000) -> bytes:
    """Verify first, decrypt second. Never returns unauthenticated plaintext."""
    try:
        s = _spec(env.algorithm)
        if not (1 <= env.kdf_iterations <= max_iterations):
            raise DecryptionError("invalid KDF parameters")
        if len(env.iv) != s["iv_len"] or len(env.salt) != 16:
            raise DecryptionError("invalid IV or salt length")
        enc_key, mac_key = derive_keys(password, env.salt, env.kdf_iterations, env.algorithm)
        header = _header(env.algorithm, env.kdf_iterations, env.salt, env.iv)
        if not s["aead"]:
            expected = hmac.new(mac_key, header + env.ciphertext, "sha256").digest()
            if len(env.mac) != MAC_LEN or not hmac.compare_digest(expected, env.mac):
                raise DecryptionError("authentication failed")
        return raw_decrypt(env.algorithm, enc_key, env.iv, env.ciphertext, aad=header)
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError("decryption failed") from exc
