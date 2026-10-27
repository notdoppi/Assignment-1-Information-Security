"""Reproducible benchmark comparing AES-GCM, legacy DES-CBC, and legacy RC4.

Method summary (see report/report.md for the justification):
  * identical plaintext bytes for every algorithm; same 256-bit key for AES-GCM
  * fresh random IV/nonce per trial, generated OUTSIDE the timed region
  * time.perf_counter_ns around ONLY cipher setup + update + finalize (+ PKCS#7 pad/unpad for CBC)
  * file I/O measured separately; web "download" measured end-to-end through the Flask app
  * warm-up runs discarded; algorithm order shuffled every trial to spread drift/noise evenly
  * GC disabled inside each timed region; correctness (decrypt == original) checked outside it
"""
from __future__ import annotations
import argparse, csv, gc, hashlib, json, os, platform, random, statistics as st, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import cryptography
from vault_crypto import ALGORITHMS, REQUIRED_ALGORITHMS, raw_decrypt, raw_encrypt
from benchmark import ciphertext_comparison, generate_fixtures

GROUPS = {"AES-GCM": "authenticated encryption (AEAD)",
          "DES-CBC": "legacy reference (obsolete)", "RC4": "legacy reference (obsolete)"}
BENCH_KEY = hashlib.sha256(b"BENCHMARK-ONLY key").digest()  # benchmark-only; DES uses the first 8 bytes


def key_for(algo: str) -> bytes:
    return BENCH_KEY[: ALGORITHMS[algo]["key_len"]]


def environment() -> dict:
    cpu, aesni = platform.processor(), None
    try:
        info = Path("/proc/cpuinfo").read_text()
        cpu = next((l.split(":", 1)[1].strip() for l in info.splitlines() if l.startswith("model name")), cpu)
        aesni = any(l.startswith("flags") and " aes" in l for l in info.splitlines())
    except OSError:
        pass
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        ossl = backend.openssl_version_text()
    except Exception:
        ossl = "unknown"
    clk = time.get_clock_info("perf_counter")
    return dict(python=sys.version.split()[0], python_impl=platform.python_implementation(),
                cryptography=cryptography.__version__, openssl=ossl, os=platform.platform(), machine=platform.machine(),
                processor=cpu, logical_cpus=os.cpu_count(), cpu_reports_aes_instructions=aesni,
                perf_counter_resolution_s=clk.resolution, perf_counter_monotonic=clk.monotonic,
                started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))


def stats(values_ns: list[int], nbytes: int) -> dict:
    s = [v / 1e9 for v in values_ns]; n = len(s); mean = st.fmean(s)
    sd = st.stdev(s) if n > 1 else 0.0
    mib = nbytes / (1024 * 1024)
    return dict(n=n, mean_s=mean, median_s=st.median(s), stdev_s=sd, min_s=min(s), max_s=max(s),
                cv_percent=(100 * sd / mean if mean else 0.0), ci95_halfwidth_s=(1.96 * sd / n ** 0.5 if n > 1 else 0.0),
                mean_throughput_MiBps=(mib / mean if mean else 0.0), median_throughput_MiBps=(mib / st.median(s) if st.median(s) else 0.0))


def bench_crypto(files: list[Path], algos: list[str], trials: int, warmup: int, seed: int, log) -> tuple[list, dict]:
    rng = random.Random(seed); raw_rows = []; sizes = {}
    for f in files:
        data = f.read_bytes(); name = f.name; kind = json.loads(
            (f.parent / "MANIFEST.json").read_text()).get(name, {}).get("kind", "unknown") if (f.parent / "MANIFEST.json").exists() else "unknown"
        log(f"  {name} ({len(data)} B, {kind})")
        ivs = {a: lambda a=a: os.urandom(ALGORITHMS[a]["iv_len"]) for a in algos}
        def one_round(record: bool, trial: int):
            order = algos[:]; rng.shuffle(order)
            for a in order:
                iv = ivs[a](); key = key_for(a)
                gc.collect(); gc.disable()
                t0 = time.perf_counter_ns(); ct = raw_encrypt(a, key, iv, data); t1 = time.perf_counter_ns()
                pt = raw_decrypt(a, key, iv, ct); t2 = time.perf_counter_ns()
                gc.enable()
                if pt != data:
                    raise AssertionError(f"round-trip mismatch: {a} on {name}")  # correctness checked outside the timer
                sizes[(name, a)] = len(ct)
                if record:
                    raw_rows.append(dict(file=name, kind=kind, plaintext_bytes=len(data), algorithm=a, trial=trial,
                                         op="encrypt", time_ns=t1 - t0, ciphertext_bytes=len(ct)))
                    raw_rows.append(dict(file=name, kind=kind, plaintext_bytes=len(data), algorithm=a, trial=trial,
                                         op="decrypt", time_ns=t2 - t1, ciphertext_bytes=len(ct)))
        for _ in range(warmup): one_round(False, -1)
        for t in range(trials): one_round(True, t)
    return raw_rows, sizes


def bench_io(files: list[Path], trials: int) -> list[dict]:
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            n = f.stat().st_size; out = Path(tmp) / "out.bin"
            for t in range(trials):
                t0 = time.perf_counter_ns(); data = f.read_bytes(); t1 = time.perf_counter_ns()
                out.write_bytes(data); t2 = time.perf_counter_ns()
                rows.append(dict(file=f.name, plaintext_bytes=n, trial=t, read_ns=t1 - t0, write_ns=t2 - t1))
    return rows


def bench_app_download(files: list[Path], algos: list[str], trials: int, log) -> list[dict]:
    """End-to-end 'download' (POST /decrypt/<id>) through the real Flask app with the production KDF cost."""
    import re
    from app import create_app
    from uploads import ALLOWED
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        app = create_app(dict(SECRET_KEY="bench-secret", DATABASE_PATH=os.path.join(tmp, "b.db"), SESSION_COOKIE_SECURE=False,
                              KDF_ITERATIONS=int(os.environ.get("KDF_ITERATIONS", "600000")), MAX_UPLOAD_BYTES=200 * 1024 * 1024))
        c = app.test_client()
        tok = lambda p: re.search(r'name="csrf_token" value="([^"]+)"', c.get(p).get_data(as_text=True)).group(1)
        c.post("/register", data=dict(username="bench", password="bench-account-pw", csrf_token=tok("/register")))
        c.post("/login", data=dict(username="bench", password="bench-account-pw", csrf_token=tok("/login")))
        import io
        for f in files:
            raw = f.read_bytes()
            ext = f.suffix.lower()
            cat = next((k for k, v in ALLOWED.items() if ext in v), None)
            if cat is None:  # random .bin / .txt are not allowed upload types: wrap with a valid PDF header
                raw, ext, cat = b"%PDF-1.4\n" + raw, ".pdf", "document"
            for a in algos:
                r = c.post("/dashboard", data=dict(csrf_token=tok("/dashboard"), file_type=cat, algorithm=a, password="bench-file-pw",
                           file=(io.BytesIO(raw), f"x{ext}")), content_type="multipart/form-data")
                import sqlite3
                conn = sqlite3.connect(os.path.join(tmp, "b.db")); fid = conn.execute("SELECT max(id) FROM encrypted_files").fetchone()[0]; conn.close()
                token = tok("/dashboard")
                for t in range(trials):
                    t0 = time.perf_counter_ns()
                    resp = c.post(f"/decrypt/{fid}", data=dict(password="bench-file-pw", csrf_token=token))
                    t1 = time.perf_counter_ns()
                    assert resp.status_code == 200 and resp.data == raw, f"download mismatch {a} {f.name}"
                    rows.append(dict(file=f.name, plaintext_bytes=len(raw), algorithm=a, trial=t, download_ns=t1 - t0))
            log(f"  app download done: {f.name}")
    return rows


def write_csv(path: Path, rows: list[dict]):
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)


def summarise(raw_rows: list[dict]) -> list[dict]:
    keyf = lambda r: (r["file"], r["kind"], r["plaintext_bytes"], r["algorithm"], r["op"], r["ciphertext_bytes"])
    groups: dict = {}
    for r in raw_rows: groups.setdefault(keyf(r), []).append(r["time_ns"])
    out = []
    for (file, kind, nb, algo, op, cb), vals in groups.items():
        out.append(dict(file=file, kind=kind, plaintext_bytes=nb, ciphertext_bytes=cb, algorithm=algo, group=GROUPS[algo], op=op,
                        **{k: (round(v, 9) if isinstance(v, float) else v) for k, v in stats(vals, nb).items()}))
    return out


def run(out: Path, fixtures: Path, trials=30, warmup=3, seed=1234, io_trials=None, app_trials=10, skip_app=False,
        only: list[str] | None = None, verbose=True) -> dict:
    log = print if verbose else (lambda *_: None)
    out.mkdir(parents=True, exist_ok=True)
    if not (fixtures / "MANIFEST.json").exists():
        log("Generating fixtures..."); generate_fixtures.generate(fixtures)
    files = sorted(p for p in fixtures.iterdir() if p.name != "MANIFEST.json" and (not only or p.name in only))
    algos = list(ALGORITHMS)
    env = environment(); env.update(trials=trials, warmup=warmup, seed=seed, algorithms=algos, files={p.name: p.stat().st_size for p in files},
                                    fixtures_manifest_sha256=hashlib.sha256((fixtures / "MANIFEST.json").read_bytes()).hexdigest(),
                                    timed_region="cipher setup + update + finalize (+PKCS7 pad/unpad); excludes IV generation, file I/O, KDF, verification",
                                    app_download_trials=None if skip_app else app_trials)
    log(f"Benchmark: {len(files)} files x {len(algos)} algorithms x {trials} trials (+{warmup} warm-up)")
    raw, _ = bench_crypto(files, algos, trials, warmup, seed, log)
    write_csv(out / "raw_results.csv", raw)
    summary = summarise(raw); write_csv(out / "summary.csv", summary)
    io_rows = bench_io(files, io_trials or trials); write_csv(out / "io_results.csv", io_rows)
    if not skip_app:
        app_files = [p for p in files if p.name in ("random_1MiB.bin", "image_synthetic.png", "document_synthetic.pdf", "video_synthetic.avi") or only]
        app_rows = bench_app_download(app_files, algos, app_trials, log); write_csv(out / "app_download_results.csv", app_rows)
    cmp = ciphertext_comparison.main(out / "ciphertext_comparison.json", fixtures)
    env["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (out / "environment.json").write_text(json.dumps(env, indent=2))
    return dict(raw_rows=len(raw), summary_rows=len(summary), environment=env)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", default=str(ROOT / "benchmark/fixtures")); ap.add_argument("--out", default=str(ROOT / "benchmark/results"))
    ap.add_argument("--trials", type=int, default=30); ap.add_argument("--warmup", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1234); ap.add_argument("--app-trials", type=int, default=10)
    ap.add_argument("--skip-app", action="store_true", help="skip the end-to-end Flask download measurement")
    a = ap.parse_args()
    r = run(Path(a.out), Path(a.fixtures), a.trials, a.warmup, a.seed, app_trials=a.app_trials, skip_app=a.skip_app)
    print(json.dumps({k: v for k, v in r.items() if k != "environment"}))
