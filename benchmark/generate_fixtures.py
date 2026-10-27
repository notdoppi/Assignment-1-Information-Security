"""Deterministic, clearly synthetic benchmark inputs (no personal data).

Every file is derived from a fixed seed so two runs on any machine give
byte-identical fixtures (verified by tests via SHA-256 in MANIFEST.json).
"""
from __future__ import annotations
import argparse, hashlib, json, random, zlib
from pathlib import Path

SEED = 20261026
KiB, MiB = 1024, 1024 * 1024
SIZE_SWEEP = {"1KiB": KiB, "64KiB": 64 * KiB, "1MiB": MiB, "10MiB": 10 * MiB, "50MiB": 50 * MiB}
WORDS = ("secure vault cipher block mode padding nonce counter feedback chaining random key stream "
         "encrypt decrypt privacy data subject consent controller processor storage retention").split()


def _rand_bytes(seed: int, n: int) -> bytes:
    return random.Random(seed).randbytes(n)  # deterministic PRNG, NOT for cryptographic use


def make_text(n: int) -> bytes:
    rng = random.Random(SEED + 1); out = bytearray()
    while len(out) < n:
        out += (" ".join(rng.choice(WORDS) for _ in range(12)) + ".\n").encode()
    return bytes(out[:n])


def make_png(path: Path) -> None:
    from PIL import Image
    w, h = 1024, 768; rng = random.Random(SEED + 2)
    img = Image.new("RGB", (w, h)); px = img.load()
    for y in range(h):
        for x in range(w):
            px[x, y] = ((x * 255 // w + rng.randrange(24)) % 256, (y * 255 // h + rng.randrange(24)) % 256,
                        ((x + y) * 255 // (w + h) + rng.randrange(24)) % 256)
    img.save(path, format="PNG", optimize=False, compress_level=1)  # PIL output is deterministic for fixed pixels


def make_pdf(path: Path) -> None:
    """Minimal hand-built multi-page PDF (no timestamp => reproducible)."""
    rng = random.Random(SEED + 3); objs = []; kids = []
    objs.append(None)  # 1 catalog placeholder
    objs.append(None)  # 2 pages placeholder
    for p in range(200):
        text = " ".join(rng.choice(WORDS) for _ in range(300))
        lines = [text[i:i + 90] for i in range(0, len(text), 90)]
        stream = "BT /F1 9 Tf 40 780 Td 11 TL " + " ".join(f"({l}) Tj T*" for l in lines) + " ET"
        c = len(objs) + 1
        objs.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream".encode())
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents {c} 0 R "
                    f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> >>".encode())
        kids.append(f"{c + 1} 0 R")
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()
    out = bytearray(b"%PDF-1.4\n"); offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    x = len(out); out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
    for o in offs: out += f"{o:010d} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    path.write_bytes(bytes(out))


def make_video(path: Path) -> bool:
    """Synthetic MJPG/AVI clip via OpenCV; returns False if OpenCV is unavailable."""
    try:
        import cv2, numpy as np
    except ImportError:
        return False
    w, h, fps = 320, 240, 25
    vw = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"MJPG"), fps, (w, h))
    rng = np.random.default_rng(SEED + 4)
    for i in range(150):
        frame = np.zeros((h, w, 3), np.uint8)
        frame[:] = (i * 255 // 150, 80, 255 - i * 255 // 150)
        cv2.circle(frame, (20 + i * 2, 120), 30, (255, 255, 255), -1)
        frame = np.clip(frame.astype(np.int16) + rng.integers(0, 12, frame.shape), 0, 255).astype(np.uint8)
        vw.write(frame)
    vw.release()
    return True


def generate(outdir: Path, include_50mib: bool = True) -> dict:
    outdir.mkdir(parents=True, exist_ok=True); manifest = {}
    def add(name, kind, data=None):
        p = outdir / name
        if data is not None: p.write_bytes(data)
        b = p.read_bytes()
        manifest[name] = dict(kind=kind, bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    for label, n in SIZE_SWEEP.items():
        if label == "50MiB" and not include_50mib: continue
        add(f"random_{label}.bin", "random-binary", _rand_bytes(SEED + n, n))
    add("text_1MiB.txt", "text", make_text(MiB))
    make_png(outdir / "image_synthetic.png"); add("image_synthetic.png", "image")
    make_pdf(outdir / "document_synthetic.pdf"); add("document_synthetic.pdf", "pdf")
    if make_video(outdir / "video_synthetic.avi"): add("video_synthetic.avi", "video")
    (outdir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    return manifest


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="benchmark/fixtures")
    ap.add_argument("--no-50mib", action="store_true")
    a = ap.parse_args()
    for k, v in generate(Path(a.out), not a.no_50mib).items(): print(f"{k:28s} {v['bytes']:>10d} B  {v['sha256'][:16]}")
