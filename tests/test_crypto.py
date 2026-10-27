"""Tests for the supported AES-GCM, DES-CBC, and RC4 configurations."""
import os
import unittest
from vault_crypto import (ALGORITHMS, REQUIRED_ALGORITHMS, DecryptionError, Envelope,
                          decrypt_bytes, encrypt_bytes, raw_decrypt, raw_encrypt)
from vault_crypto.ciphers import UnsupportedAlgorithm

KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
GCM_IV = bytes.fromhex("000102030405060708090a0b")
PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
ITER = 1000
SIZES = [0, 1, 7, 8, 15, 16, 17, 255, 4096, 100_003]

class RoundTrip(unittest.TestCase):
    def test_only_three_algorithms_are_exposed(self):
        self.assertEqual(set(ALGORITHMS), {"AES-GCM", "DES-CBC", "RC4"})
        self.assertEqual(REQUIRED_ALGORITHMS, ("AES-GCM", "DES-CBC", "RC4"))

    def test_every_algorithm_every_size(self):
        for algo in ALGORITHMS:
            for n in SIZES:
                with self.subTest(algo=algo, size=n):
                    data = os.urandom(n)
                    env = encrypt_bytes(data, "correct horse", algo, ITER)
                    self.assertEqual(decrypt_bytes(env, "correct horse"), data)

    def test_gcm_raw_roundtrip_and_tag(self):
        for n in SIZES:
            data = os.urandom(n)
            ct = raw_encrypt("AES-GCM", KEY, GCM_IV, data)
            self.assertEqual(len(ct), len(data) + 16)
            self.assertEqual(raw_decrypt("AES-GCM", KEY, GCM_IV, ct), data)

    def test_fresh_randomness_gives_different_ciphertexts(self):
        for algo in ALGORITHMS:
            a = encrypt_bytes(b"same plaintext" * 10, "pw-pw-pw-pw", algo, ITER)
            b = encrypt_bytes(b"same plaintext" * 10, "pw-pw-pw-pw", algo, ITER)
            self.assertNotEqual(a.salt, b.salt)
            self.assertNotEqual(a.ciphertext, b.ciphertext, algo)

    def test_removed_aes_modes_are_rejected(self):
        for algo in ("AES-CBC", "AES-CFB", "AES-OFB", "AES-CTR", "AES-ECB"):
            with self.subTest(algo=algo), self.assertRaises(UnsupportedAlgorithm):
                encrypt_bytes(b"x", "pw-pw-pw-pw", algo, ITER)

class Tamper(unittest.TestCase):
    def _env(self, algo):
        return encrypt_bytes(os.urandom(300), "right-password", algo, ITER)

    def test_wrong_password(self):
        for algo in ALGORITHMS:
            with self.assertRaises(DecryptionError, msg=algo):
                decrypt_bytes(self._env(algo), "wrong-password")

    def test_flipped_ciphertext_bit_is_rejected_never_returned(self):
        for algo in ALGORITHMS:
            e = self._env(algo); ct = bytearray(e.ciphertext); ct[5] ^= 1; e.ciphertext = bytes(ct)
            with self.assertRaises(DecryptionError, msg=algo): decrypt_bytes(e, "right-password")

    def test_truncated_and_extended_ciphertext(self):
        for algo in ALGORITHMS:
            for mut in (lambda c: c[:-1], lambda c: c + b"\x00", lambda c: b""):
                e = self._env(algo); e.ciphertext = mut(e.ciphertext)
                with self.assertRaises(DecryptionError, msg=algo): decrypt_bytes(e, "right-password")

    def test_tampered_iv_salt_mac_iterations_algorithm(self):
        for algo in ALGORITHMS:
            e = self._env(algo)
            if e.iv:
                e2 = Envelope(**{**e.__dict__, "iv": bytes([e.iv[0] ^ 1]) + e.iv[1:]})
                with self.assertRaises(DecryptionError): decrypt_bytes(e2, "right-password")
            e3 = Envelope(**{**e.__dict__, "salt": bytes([e.salt[0] ^ 1]) + e.salt[1:]})
            with self.assertRaises(DecryptionError): decrypt_bytes(e3, "right-password")
            e4 = Envelope(**{**e.__dict__, "kdf_iterations": ITER + 1})
            with self.assertRaises(DecryptionError): decrypt_bytes(e4, "right-password")
            if e.mac:
                e5 = Envelope(**{**e.__dict__, "mac": bytes(32)})
                with self.assertRaises(DecryptionError): decrypt_bytes(e5, "right-password")

    def test_invalid_metadata_and_algorithm_swap(self):
        e = self._env("AES-GCM")
        for bad in (dict(algorithm="NOPE"), dict(kdf_iterations=0), dict(kdf_iterations=10**12),
                    dict(iv=b"short"), dict(salt=b"")):
            with self.assertRaises(DecryptionError, msg=str(bad)):
                decrypt_bytes(Envelope(**{**e.__dict__, **bad}), "right-password")
        with self.assertRaises(DecryptionError):
            decrypt_bytes(Envelope(**{**e.__dict__, "algorithm": "DES-CBC"}), "right-password")

if __name__ == "__main__": unittest.main()
