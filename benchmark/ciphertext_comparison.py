"""Controlled ciphertext experiments (fixed key/IV => reproducible lab output).

The fixed key and IV below exist ONLY so that two runs of this script give the
same numbers. They must never be reused for real data: reusing an AES-GCM nonce breaks its security guarantees.
"""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from vault_crypto import ALGORITHMS, REQUIRED_ALGORITHMS, DecryptionError, raw_decrypt, raw_encrypt

LAB_KEY = hashlib.sha256(b"LAB-ONLY-KEY: never use for real data").digest()          # 32 bytes
LAB_IV = hashlib.sha256(b"LAB-ONLY-IV: never use for real data").digest()[:16]       # 16 bytes
MODES = list(REQUIRED_ALGORITHMS)


def _iv(algo):  # GCM uses a 96-bit nonce
    return LAB_IV[:12] if algo == "AES-GCM" else LAB_IV[:ALGORITHMS[algo]["iv_len"]]


def _enc(algo, data, key=LAB_KEY, iv=None):
    return raw_encrypt(algo, key[:ALGORITHMS[algo]["key_len"]], iv if iv is not None else _iv(algo), data)


def hamming_fraction(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    if n == 0: return 0.0
    return sum(bin(x ^ y).count("1") for x, y in zip(a[:n], b[:n])) / (8 * n)


def run(plaintext: bytes) -> dict:
    res: dict = {"note": "Fixed LAB key/IV for reproducibility only.", "plaintext_bytes": len(plaintext),
                 "plaintext_sha256": hashlib.sha256(plaintext).hexdigest()}
    cts = {m: _enc(m, plaintext) for m in MODES}
    res["same_key_iv_plaintext"] = {m: dict(ciphertext_bytes=len(c), overhead_bytes=len(c) - len(plaintext),
                                            first_16_bytes_hex=c[:16].hex(), sha256=hashlib.sha256(c).hexdigest())
                                    for m, c in cts.items()}
    # Pairwise differences are descriptive only; these algorithms have different formats and security properties.
    res["pairwise_bit_difference_fraction"] = {
        f"{a} vs {b}": round(hamming_fraction(cts[a], cts[b]), 4) for i, a in enumerate(MODES) for b in MODES[i + 1:]}
    res["pairwise_first_block_identical"] = {
        f"{a} vs {b}": cts[a][:16] == cts[b][:16] for i, a in enumerate(MODES) for b in MODES[i + 1:]}
    # Determinism: same (key, IV) twice vs fresh random IV
    det, fresh = {}, {}
    for m in MODES:
        det[m] = _enc(m, plaintext) == _enc(m, plaintext)
        iv1, iv2 = os.urandom(len(_iv(m))), os.urandom(len(_iv(m)))
        c1, c2 = _enc(m, plaintext, iv=iv1), _enc(m, plaintext, iv=iv2)
        fresh[m] = dict(identical=c1 == c2, bit_difference_fraction=round(hamming_fraction(c1, c2), 4))
    res["same_key_same_iv_twice_identical"] = det
    res["same_key_fresh_random_iv_twice"] = fresh
    res["note_fresh_iv"] = "Values of bit_difference_fraction here use os.urandom and vary slightly between runs (about 0.5)."
    # Padding / size behaviour
    lens = [0, 1, 15, 16, 17, 31, 32, 1000]
    res["ciphertext_size_by_plaintext_length"] = {m: {str(n): len(_enc(m, bytes(n))) for n in lens} for m in MODES}
    # Repeated-block plaintext: ECB is shown only as a demonstration of why it is excluded.
    blk = bytes.fromhex("00112233445566778899aabbccddeeff"); rep = blk * 8
    def dup(c): 
        bl = [c[i:i + 16] for i in range(0, len(rep), 16)]
        return len(bl) - len(set(bl))
    ecb = Cipher(algorithms.AES(LAB_KEY), modes.ECB()).encryptor()
    res["repeated_block_plaintext_duplicate_ciphertext_blocks_of_8"] = {
        **{m: dup(_enc(m, rep)) for m in MODES}, "AES-ECB (demonstration only, NOT used)": dup(ecb.update(rep) + ecb.finalize())}
    # Single-bit error propagation: flip bit 0 of ciphertext byte 3 in block 2 (10 plaintext blocks)
    n_blocks = 10; pt = bytes((i * 7 + 3) % 256 for i in range(16 * n_blocks)); prop = {}
    for m in MODES:
        ct = bytearray(_enc(m, pt)); ct[min(16 * 2 + 3, len(ct)-1)] ^= 0x01
        try:
            out = raw_decrypt(m, LAB_KEY[:ALGORITHMS[m]["key_len"]], _iv(m), bytes(ct))
        except DecryptionError:
            prop[m] = dict(result="decryption rejected (authentication/padding failure)", plaintext_returned=False); continue
        per_block = [sum(bin(a ^ b).count("1") for a, b in zip(out[i*16:(i+1)*16], pt[i*16:(i+1)*16])) for i in range(n_blocks)]
        prop[m] = dict(result="decrypted with errors", plaintext_returned=True, wrong_bits_per_plaintext_block=per_block,
                       corrupted_blocks=[i for i, v in enumerate(per_block) if v])
    res["bit_flip_in_ciphertext_block_2"] = prop
    return res


def main(out: Path, fixture_dir: Path | None = None) -> dict:
    pt = b""
    if fixture_dir and (fixture_dir / "text_1MiB.txt").exists():
        pt = (fixture_dir / "text_1MiB.txt").read_bytes()[:4096]
    pt = pt or (b"The quick brown fox jumps over the lazy dog. " * 100)[:4096]
    res = run(pt); out.write_text(json.dumps(res, indent=2, sort_keys=True)); return res
