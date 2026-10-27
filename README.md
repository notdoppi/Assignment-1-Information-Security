# Secure Private Data Vault (Information Security – Assignment 1)

A Flask web application where users register, log in, and store **ID-card images, PDF/DOC/XLS documents and videos**
encrypted with **AES, DES and RC4**, plus a reproducible **AES-mode benchmark** (CBC, CFB, OFB, CTR, + GCM) and a technical report.

> **Educational project.** DES and RC4 are obsolete/insecure and are present only because the assignment requires them.
> Nothing here is certified as GDPR / UU PDP compliant, and it is not claimed to be production-secure (see *Known limitations*).

## Project layout
```
app.py                 Flask app factory (routes, auth, CSRF, security headers)
uploads.py             filename / extension / MIME / magic-byte / size validation
vault_crypto/          AES-CBC/CFB/OFB/CTR/GCM, DES-CBC, RC4 + password envelope (PBKDF2, HKDF, HMAC)
database/              schema.sql + db.py (sqlite3; ciphertext stored as BLOB)
templates/ static/     UI (original look preserved)
benchmark/             fixtures generator, runner, ciphertext experiments, plots, results/, graphs/
tests/                 unittest suite (pytest-compatible): crypto, web app, benchmark
report/                report.md, report.pdf, build_report.py
original_submission/   untouched copy of the original my_web_crypto.zip
```

## Setup
Python 3.10+ is required (developed and tested with 3.12).
```bash
python -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt                          # Flask, cryptography
pip install -r requirements-benchmark.txt                # needed for the benchmark graphs AND to run the full test suite
cp .env.example .env                                     # then edit .env
python -c "import secrets; print(secrets.token_hex(32))" # paste the output as SECRET_KEY in .env
```
`.env` variables: `SECRET_KEY` (**required**, the app refuses to start without it), `DATABASE_PATH`, `MAX_UPLOAD_MB`,
`KDF_ITERATIONS` (default 600000), `SESSION_COOKIE_SECURE` (`1` behind HTTPS; `.env.example` sets `0` for plain-http localhost),
`HOST`, `PORT`.

## Database initialisation
The schema (`database/schema.sql`) is created automatically on start. To create it explicitly:
```bash
python -m database.db instance/vault.db
```
There are no migrations: to reset, stop the app and delete `instance/vault.db`.

## Run the application
```bash
python app.py                 # http://127.0.0.1:5000  (debug mode is OFF)
# or:  flask --app "app:create_app" run
```
For anything beyond local testing run behind a real WSGI server (e.g. `gunicorn "app:create_app()"`) and HTTPS, with `SESSION_COOKIE_SECURE=1`.

Usage: register → log in → choose a file, its category, an algorithm and a **per-file encryption password** → *Proses Enkripsi & Simpan*.
To get the file back, type the same password next to the file and press the unlock button. The password is never stored; a lost password means the data is unrecoverable.
The algorithm `ALL` stores three independent encrypted copies (AES-CBC, DES-CBC, RC4) of the same upload.

## Run the tests
The tests need **both** requirement files (`tests/test_benchmark.py` imports `matplotlib`; the fixture generator needs `pillow`):
```bash
pip install -r requirements.txt -r requirements-benchmark.txt
python -m unittest discover -s tests -t . -v      # stdlib runner; no pytest needed
# optional: pip install pytest && pytest -q
```
If you see `ModuleNotFoundError: No module named 'matplotlib'`, the benchmark requirements are not installed in the active virtual environment.
`test_crypto` and `test_webapp` alone need only `requirements.txt`: `python -m unittest tests.test_crypto tests.test_webapp`.
The tests do not depend on your local `.env` (the secure-cookie default test stubs `.env` loading and restores `os.environ`).
The suite includes a short benchmark run (small configuration) and takes roughly 30–60 s.

## Run the benchmark and regenerate every artefact
```bash
python -m benchmark.generate_fixtures                  # deterministic synthetic inputs -> benchmark/fixtures/ (+MANIFEST.json)
python -m benchmark.run_benchmark --trials 30 --warmup 3 --app-trials 10
python -m benchmark.make_plots                         # benchmark/graphs/*.png
python report/build_report.py                          # report/report.md (tables from the CSVs) and report/report.pdf (PDF needs pandoc + LibreOffice)
```
Results land in `benchmark/results/`: `raw_results.csv` (every trial), `summary.csv` (mean/median/stdev/min/max/CI/throughput),
`io_results.csv` (file read/write, measured separately), `app_download_results.csv` (end-to-end Flask download),
`ciphertext_comparison.json`, `environment.json`. Run the benchmark on an otherwise idle machine; timings differ per machine.
Options: `--trials`, `--warmup`, `--seed`, `--app-trials`, `--skip-app`.

## Algorithms and modes
| Name | Role | Notes |
|---|---|---|
| AES-256-CBC | required mode, app default | PKCS#7 padding; error in one ciphertext block garbles that block and flips bits in the next |
| AES-256-CFB (128-bit) | required mode | stream-like, no padding; error garbles the next block |
| AES-256-OFB | required mode | no padding; bit errors do not propagate |
| AES-256-CTR | required mode | no padding; parallelisable; bit errors do not propagate; never reuse a nonce |
| AES-256-GCM | extra | authenticated encryption (AEAD) |
| DES-CBC | required by assignment | 56-bit key: **broken**; implemented as 3DES with K1=K2=K3 (identical to DES) |
| RC4 | required by assignment | stream cipher (**not** a block-cipher mode): biased, **broken** |

Envelope (every stored file): `PBKDF2-HMAC-SHA256 (random 16-byte salt, 600k iterations) → HKDF-Expand → separate encryption key and MAC key`;
random IV/nonce per file; **HMAC-SHA256 over (header ‖ ciphertext)** is verified *before* decrypting (AES-GCM uses its own tag).
Wrong passwords and tampered data are indistinguishable by design and never yield output.

## Known limitations
* Educational project; not audited; no claim of legal compliance with GDPR or UU PDP.
* DES and RC4 are cryptographically broken; use AES-GCM for anything real.
* The slide says data must be encrypted "with all of these algorithms". Implemented as: the user may pick one algorithm per file, or `ALL` for three independent copies. **Confirm the intended interpretation with the lecturer** (e.g. layered encryption).
* Encrypted bytes live in SQLite BLOBs, simple and satisfying "in a database", but files are held in memory (default limit 100 MB) – not suited to multi-gigabyte video.
* Filenames, category, sizes and timestamps are stored as plaintext metadata.
* Per-file passwords are chosen by the user; there is no recovery, no key escrow, no 2FA, no password reset, no account deletion.
* The login throttle is in-process memory (reset on restart, per worker).
* Bootstrap/Google Fonts are loaded from CDNs by the templates (needs internet in the browser).
* Magic-byte checks reduce, but do not eliminate, malicious uploads; no antivirus scanning. Files are never executed or served inline.
* Benchmark numbers are specific to the machine they were produced on.
