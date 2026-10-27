"""Time the password KDF alone (it dominates end-to-end web downloads)."""
import json, os, statistics as st, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from vault_crypto.ciphers import derive_keys

def main(out: Path, trials: int = 20, iterations: int = 600_000):
    salt = bytes(16); ts = []
    derive_keys("warm-up-password", salt, iterations, "AES-CBC")
    for _ in range(trials):
        t0 = time.perf_counter_ns(); derive_keys("benchmark-password", salt, iterations, "AES-CBC"); ts.append((time.perf_counter_ns() - t0) / 1e6)
    res = dict(iterations=iterations, trials=trials, mean_ms=st.fmean(ts), median_ms=st.median(ts), stdev_ms=st.stdev(ts), min_ms=min(ts), max_ms=max(ts))
    out.write_text(json.dumps(res, indent=2)); return res

if __name__ == "__main__":
    print(main(Path(__file__).resolve().parent / "results" / "kdf_timing.json"))
