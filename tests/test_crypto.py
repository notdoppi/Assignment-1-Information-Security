"""Unit tests for vault_crypto (known-answer vectors, round trips, tamper detection)."""
import os
import unittest

from vault_crypto import (ALGORITHMS, REQUIRED_AES_MODES, DecryptionError, Envelope,
                          decrypt_bytes, encrypt_bytes, raw_decrypt, raw_encrypt)
from vault_crypto.ciphers import UnsupportedAlgorithm

# NIST SP 800-38A, AES-256 vectors (first plaintext block)
KEY = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
PT = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CTR0 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
ITER = 1000  # low only to keep tests fast; the app default is 600,000
SIZES = [0, 1, 7, 8, 15, 16, 17, 255, 4096, 100_003]


class KnownAnswer(unittest.TestCase):
    def test_aes_cbc(self):
        self.assertEqual(raw_encrypt("AES-CBC", KEY, IV, PT)[:16].hex(), "f58c4c04d6e5f1ba779eabfb5f7bfbd6")

    def test_aes_cfb(self):
        self.assertEqual(raw_encrypt("AES-CFB", KEY, IV, PT).hex(), "dc7e84bfda79164b7ecd8486985d3860")

    def test_aes_ofb(self):
        self.assertEqual(raw_encrypt("AES-OFB", KEY, IV, PT).hex(), "dc7e84bfda79164b7ecd8486985d3860")

    def test_aes_ctr(self):
        self.assertEqual(raw_encrypt("AES-CTR", KEY, CTR0, PT).hex(), "601ec313775789a5b7a7f504bbf3d228")

    def test_des_classic_vector(self):  # key 133457799BBCDFF1, zero IV => first CBC block == ECB block
        out = raw_encrypt("DES-CBC", bytes.fromhex("133457799BBCDFF1"), bytes(8), bytes.fromhex("0123456789ABCDEF"))
        self.assertEqual(out[:8].hex().upper(), "85E813540F0AB405")

    def test_rc4_rfc6229(self):  # 40-bit key 0102030405, first 8 keystream bytes
        from cryptography.hazmat.primitives.ciphers import Cipher
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import ARC4
        ks = Cipher(ARC4(bytes.fromhex("0102030405")), mode=None).encryptor().update(bytes(8))
        self.assertEqual(ks.hex(), "b2396305f03dc027")


class RoundTrip(unittest.TestCase):
    def test_every_algorithm_every_size(self):
        for algo in ALGORITHMS:
            for n in SIZES:
                with self.subTest(algo=algo, size=n):
                    data = os.urandom(n)
                    env = encrypt_bytes(data, "correct horse", algo, ITER)
                    self.assertEqual(decrypt_bytes(env, "correct horse"), data)

    def test_required_modes_raw_roundtrip_including_empty(self):
        for algo in REQUIRED_AES_MODES:
            for n in SIZES:
                with self.subTest(algo=algo, size=n):
                    iv = os.urandom(16)
                    data = os.urandom(n)
                    self.assertEqual(raw_decrypt(algo, KEY, iv, raw_encrypt(algo, KEY, iv, data)), data)

    def test_padding_behaviour(self):
        iv = os.urandom(16)
        self.assertEqual(len(raw_encrypt("AES-CBC", KEY, iv, b"")), 16)        # empty -> one full pad block
        self.assertEqual(len(raw_encrypt("AES-CBC", KEY, iv, bytes(16))), 32)  # full block -> extra block
        self.assertEqual(len(raw_encrypt("AES-CBC", KEY, iv, bytes(17))), 32)
        for algo in ("AES-CFB", "AES-OFB", "AES-CTR"):
            self.assertEqual(len(raw_encrypt(algo, KEY, iv, bytes(17))), 17)    # no padding
        self.assertEqual(len(raw_encrypt("RC4", KEY, b"", bytes(17))), 17)
        self.assertEqual(len(raw_encrypt("DES-CBC", KEY[:8], iv[:8], bytes(8))), 16)

    def test_fresh_randomness_gives_different_ciphertexts(self):
        for algo in ALGORITHMS:
            a = encrypt_bytes(b"same plaintext" * 10, "pw-pw-pw-pw", algo, ITER)
            b = encrypt_bytes(b"same plaintext" * 10, "pw-pw-pw-pw", algo, ITER)
            self.assertNotEqual(a.salt, b.salt)
            self.assertNotEqual(a.ciphertext, b.ciphertext, algo)  # salt differs -> key differs, even for RC4

    def test_same_key_and_iv_is_deterministic(self):
        iv = bytes(16)
        self.assertEqual(raw_encrypt("AES-CTR", KEY, iv, b"abc"), raw_encrypt("AES-CTR", KEY, iv, b"abc"))

    def test_different_modes_give_different_ciphertext(self):
        data = os.urandom(64)
        outs = {m: raw_encrypt(m, KEY, IV, data)[:64] for m in REQUIRED_AES_MODES}
        self.assertEqual(len(set(outs.values())), 4)


class Tamper(unittest.TestCase):
    def _env(self, algo):
        return encrypt_bytes(os.urandom(300), "right-password", algo, ITER)

    def test_wrong_password(self):
        for algo in ALGORITHMS:
            with self.assertRaises(DecryptionError, msg=algo):
                decrypt_bytes(self._env(algo), "wrong-password")

    def test_flipped_ciphertext_bit_is_rejected_never_returned(self):
        for algo in ALGORITHMS:
            e = self._env(algo)
            ct = bytearray(e.ciphertext); ct[5] ^= 1; e.ciphertext = bytes(ct)
            with self.assertRaises(DecryptionError, msg=algo):
                decrypt_bytes(e, "right-password")

    def test_truncated_and_extended_ciphertext(self):
        for algo in ALGORITHMS:
            for mut in (lambda c: c[:-1], lambda c: c + b"\x00", lambda c: b""):
                e = self._env(algo); e.ciphertext = mut(e.ciphertext)
                with self.assertRaises(DecryptionError, msg=algo):
                    decrypt_bytes(e, "right-password")

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

    def test_invalid_metadata(self):
        e = self._env("AES-CBC")
        for bad in (dict(algorithm="NOPE"), dict(kdf_iterations=0), dict(kdf_iterations=10**12),
                    dict(iv=b"short"), dict(salt=b""), dict(mac=b"")):
            with self.assertRaises(DecryptionError, msg=str(bad)):
                decrypt_bytes(Envelope(**{**e.__dict__, **bad}), "right-password")

    def test_algorithm_swap_is_rejected(self):
        e = self._env("AES-CFB")
        with self.assertRaises(DecryptionError):
            decrypt_bytes(Envelope(**{**e.__dict__, "algorithm": "AES-OFB"}), "right-password")

    def test_unsupported_algorithm_on_encrypt(self):
        with self.assertRaises(UnsupportedAlgorithm):
            encrypt_bytes(b"x", "pw-pw-pw-pw", "AES-ECB", ITER)


class ErrorPropagation(unittest.TestCase):
    """Documents the mode properties that the report discusses (raw, unauthenticated)."""
    def _flip(self, algo, n_blocks=6):
        iv = os.urandom(16); data = os.urandom(16 * n_blocks)
        ct = bytearray(raw_encrypt(algo, KEY, iv, data)); ct[16 * 2 + 3] ^= 0x01  # block 2
        try:
            out = raw_decrypt(algo, KEY, iv, bytes(ct))
        except DecryptionError:
            return None
        return [i for i in range(16 * n_blocks) if out[i] != data[i]]

    def test_ctr_ofb_flip_one_byte_only(self):
        for algo in ("AES-CTR", "AES-OFB"):
            self.assertEqual(self._flip(algo), [16 * 2 + 3])

    def test_cbc_corrupts_block_and_flips_one_bit_in_next(self):
        diff = self._flip("AES-CBC")
        blocks = sorted({i // 16 for i in diff})
        self.assertEqual(blocks, [2, 3])
        self.assertEqual([i for i in diff if i // 16 == 3], [16 * 3 + 3])

    def test_cfb_flips_bit_then_garbles_next_block(self):
        diff = self._flip("AES-CFB")
        self.assertIn(16 * 2 + 3, diff)
        self.assertEqual(sorted({i // 16 for i in diff}), [2, 3])
        self.assertGreater(len([i for i in diff if i // 16 == 3]), 8)


if __name__ == "__main__":
    unittest.main()
