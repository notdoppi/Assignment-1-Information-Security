# Secure Private Data Vault
**Information Security — Assignment 1**

A Flask web application for registering, logging in, and storing files encrypted with **AES-GCM, DES-CBC, or RC4**. The project also includes a reproducible benchmark comparing these three algorithms and a technical report.

> **Educational project.** DES and RC4 are obsolete and cryptographically insecure; they are included only for academic comparison. Use AES-GCM for real data. This project has not been security-audited and does not claim compliance with GDPR or Indonesia's UU PDP.

## Features

- User registration and login.
- Encrypted storage for supported uploads, including images and common document formats.
- Per-file encryption passwords; passwords are not stored, so forgotten passwords cannot be recovered.
- Algorithm selection for each file, with an `ALL` option that stores three independent encrypted copies using AES-GCM, DES-CBC, and RC4.
- SQLite database storage for encrypted file contents.
- Input validation for filenames, extensions, MIME types, magic bytes, and file size.
- Benchmark scripts, plots, test suite, and a generated Markdown/PDF report.

## Project layout

```text
app.py                  Flask app factory (routes, authentication, CSRF, security headers)
uploads.py              Filename, extension, MIME, magic-byte, and size validation
vault_crypto/           AES-GCM, DES-CBC, RC4, and password-envelope implementation
database/               SQLite schema and database access
templates/ static/      Web interface
benchmark/              Synthetic fixtures, benchmark runner, experiments, plots, and results
tests/                  Unit tests for cryptography, web app, and benchmark
report/                 Report source and generated Markdown/PDF report
original_submission/     Copy of the original submission, if included
```

## Requirements

- Python 3.10 or newer (developed and tested with Python 3.12).
- Install the main dependencies and the benchmark/test dependencies.

## Setup

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r requirements-benchmark.txt
Copy-Item .env.example .env
```

Open `.env` and set `SECRET_KEY` to a newly generated random value. Generate one with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

### macOS / Linux

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-benchmark.txt
cp .env.example .env
```

Generate a secret key with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the generated value into `.env` as `SECRET_KEY`.

### Environment variables

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Required Flask secret key. The application should refuse to start without it. |
| `DATABASE_PATH` | Optional database path. |
| `MAX_UPLOAD_MB` | Maximum upload size, subject to the configured application limit. |
| `KDF_ITERATIONS` | Password-based key derivation iterations; default is 600,000 if unchanged in configuration. |
| `SESSION_COOKIE_SECURE` | Set to `1` when serving over HTTPS; local HTTP development typically uses `0`. |
| `HOST` / `PORT` | Optional host and port configuration. |

Do not commit `.env`, passwords, or other secrets to Git.

## Database

The SQLite schema is initialized automatically when the application starts. To initialize a database explicitly, if supported by the current checkout:

```bash
python -m database.db instance/vault.db
```

There are no database migrations. To reset a local database, stop the application and remove the configured database file. **This permanently deletes the data in that database**, so back it up first if needed.

## Run the application

```bash
python app.py
```

The local development server is typically available at `http://127.0.0.1:5000`. Alternatively, if supported by the current Flask setup:

```bash
flask --app "app:create_app" run
```

For deployment beyond local testing, use a production WSGI server and HTTPS, and configure `SESSION_COOKIE_SECURE=1` when HTTPS is enabled. The built-in development server is not intended for production.

### Basic usage

1. Register an account and log in.
2. Choose a supported file and category.
3. Select an algorithm and enter a per-file encryption password.
4. Encrypt and save the file.
5. To retrieve it, enter the same password and unlock/download the file.

The application does not store the per-file password. If it is lost, the encrypted file cannot be recovered through the application.

The `ALL` option stores three independent encrypted copies—one each using AES-GCM, DES-CBC, and RC4. It does not mean that the same file is encrypted in layers.

## Algorithms

| Algorithm | Role | Security notes |
|---|---|---|
| **AES-GCM** | Recommended algorithm | Authenticated encryption (AEAD); detects ciphertext tampering when verification is correctly performed. |
| **DES-CBC** | Legacy academic comparison | DES has an effective 56-bit key and is broken. The implementation may use a TripleDES primitive with all three keys identical to reproduce DES behavior. |
| **RC4** | Legacy academic comparison | A stream cipher, not a block-cipher mode. Its keystream biases make it insecure. |

AES-GCM, DES-CBC, and RC4 are not equally secure. **Use AES-GCM for real data; do not use DES-CBC or RC4 to protect sensitive information.**

### Password envelope and integrity

The project uses a password-based key derivation and key-separation design. In the current implementation, check the source code and generated report for the exact parameters and envelope format. For non-AEAD legacy algorithms, integrity protection should be verified before decryption; AES-GCM provides its own authentication tag.

## Tests

Install both dependency sets before running the full suite. The benchmark requirements may include packages such as `matplotlib` and `Pillow` used by benchmark tests and fixture generation.

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements-benchmark.txt
python -m unittest discover -s tests -t . -v
```

If `pytest` is installed, you may also run:

```bash
pytest -q
```

If you encounter `ModuleNotFoundError` for `matplotlib` or `PIL`, install the benchmark requirements in the **same Python environment** selected in VS Code.

## Run the benchmark and regenerate the report

Run these commands from the project root:

```bash
python -m benchmark.generate_fixtures
python -m benchmark.run_benchmark --trials 30 --warmup 3 --app-trials 10
python -m benchmark.make_plots
python report/build_report.py
```

The benchmark runner may support additional options such as `--trials`, `--warmup`, `--seed`, `--app-trials`, and `--skip-app`; run it with `--help` to confirm the options in your checkout.

Benchmark outputs are written under `benchmark/results/`, and graphs under `benchmark/graphs/`. Typical result files include:

- `raw_results.csv` — individual timing measurements.
- `summary.csv` — aggregate timing and throughput statistics.
- `io_results.csv` — separate file read/write timings.
- `app_download_results.csv` — end-to-end application download timings, when app trials are enabled.
- `environment.json` — environment and benchmark configuration metadata.
- Additional JSON files for ciphertext and cryptographic experiments, depending on the current implementation.

The report generator creates `report/report.md` and may create `report/report.pdf` when its PDF dependency is installed. Check the current `build_report.py` implementation for its exact PDF-generation requirements.

Run benchmarks on an otherwise idle machine. Results depend on the CPU, operating system, Python version, cryptographic library, and workload; do not treat them as universal performance rankings.

## Known limitations

- This is an educational project and has not undergone a professional security audit.
- DES and RC4 are obsolete and insecure; they are included for academic comparison only.
- The interpretation of “encrypt with all algorithms” depends on the assignment. This implementation's `ALL` option creates independent copies rather than layered encryption; confirm the intended interpretation with the lecturer.
- Uploaded files may be held in memory and may have a configured size limit; this approach is not designed for multi-gigabyte videos.
- Filenames, categories, sizes, timestamps, or other metadata may be stored without encryption.
- There is no recovery mechanism for forgotten per-file passwords unless one is explicitly implemented.
- Login throttling, if implemented in process memory, may reset on restart and may not be shared across multiple workers.
- External assets loaded from CDNs require a network connection in the browser.
- File validation reduces risk but does not replace antivirus scanning or a comprehensive upload-security review.
- Benchmark measurements are specific to the machine and configuration used to generate them.
- This project makes no claim of GDPR or UU PDP compliance.

## Academic use and responsible handling

Use synthetic or non-sensitive files for testing. Do not upload real identity-card images or confidential documents to an unreviewed deployment. Keep secrets and local data out of version control, and document any changes to the cryptographic implementation before submitting the project.
