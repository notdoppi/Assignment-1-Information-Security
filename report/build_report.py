"""Build report/report.md (numbers/tables read from benchmark/results) and report/report.pdf (pandoc + LibreOffice if present)."""
from __future__ import annotations
import csv, json, re, shutil, statistics as st, subprocess, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
R = ROOT / "benchmark/results"; G = ROOT / "benchmark/graphs"; OUT = ROOT / "report"
ORDER = ["AES-CBC", "AES-CFB", "AES-OFB", "AES-CTR", "AES-GCM", "DES-CBC", "RC4"]
AES4 = ORDER[:4]
rd = lambda p: list(csv.DictReader(open(p, newline="")))
S, A, IO = rd(R / "summary.csv"), rd(R / "app_download_results.csv"), rd(R / "io_results.csv")
ENV = json.loads((R / "environment.json").read_text()); CMP = json.loads((R / "ciphertext_comparison.json").read_text())
KDF = json.loads((R / "kdf_timing.json").read_text())
g = lambda f, a, op: next(r for r in S if r["file"] == f and r["algorithm"] == a and r["op"] == op)
fl = lambda x, d=2: f"{float(x):.{d}f}"
ms = lambda r, k: float(r[k]) * 1000
table = lambda head, rows: "\n".join(["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])

# ---- tables from real data
def stat_table(fn):
    rows = []
    for a in ORDER:
        e, d = g(fn, a, "encrypt"), g(fn, a, "decrypt")
        rows.append([a, fl(ms(e, "mean_s"), 2), fl(ms(e, "stdev_s"), 2), fl(e["mean_throughput_MiBps"], 0),
                     fl(ms(d, "mean_s"), 2), fl(ms(d, "stdev_s"), 2), fl(d["mean_throughput_MiBps"], 0)])
    return table(["Algorithm", "Enc mean ms", "Enc SD ms", "Enc MiB/s", "Dec mean ms", "Dec SD ms", "Dec MiB/s"], rows) + \
        "\n\n(Medians, min/max, CV and 95 % CI are in `benchmark/results/summary.csv`; ciphertext sizes are in Section 11.)"

sweep = ["random_1KiB.bin", "random_64KiB.bin", "random_1MiB.bin", "random_10MiB.bin", "random_50MiB.bin"]
lab = {"random_1KiB.bin": "1 KiB", "random_64KiB.bin": "64 KiB", "random_1MiB.bin": "1 MiB", "random_10MiB.bin": "10 MiB", "random_50MiB.bin": "50 MiB"}
def sweep_table(op):
    rows = []
    for a in ORDER:
        rows.append([a] + [fl(g(f, a, op)["mean_throughput_MiBps"], 0) for f in sweep])
    fastest = ["**" + min(AES4, key=lambda a: float(g(f, a, op)["mean_s"])) + "**" for f in sweep]
    rows.append(["*fastest required mode*"] + fastest)
    return table(["Mean throughput (MiB/s)"] + [lab[f] for f in sweep], rows)

kinds = [("text_1MiB.txt", "text 1 MiB"), ("image_synthetic.png", "PNG image"), ("document_synthetic.pdf", "PDF"), ("video_synthetic.avi", "AVI video"), ("random_1MiB.bin", "random 1 MiB")]
type_tbl = table(["Encryption MiB/s"] + [k[1] + f" ({int(g(k[0], 'AES-CBC', 'encrypt')['plaintext_bytes'])//1024} KiB)" for k in kinds],
                 [[a] + [fl(g(k[0], a, "encrypt")["mean_throughput_MiBps"], 0) for k in kinds] for a in ORDER])
app_files = sorted({r["file"] for r in A})
app_tbl = table(["Mean download (ms)"] + app_files, [[a] + [fl(st.fmean(int(r["download_ns"]) for r in A if r["file"] == f and r["algorithm"] == a) / 1e6, 1) for f in app_files] for a in ORDER])
n_app = len([r for r in A if r["file"] == app_files[0] and r["algorithm"] == "AES-CBC"])
app_all = [int(r["download_ns"]) / 1e6 for r in A]
io_tbl = table(["File", "Size (B)", "Read mean (ms)", "Write mean (ms)"],
               [[f, next(int(r["plaintext_bytes"]) for r in IO if r["file"] == f), fl(st.fmean(int(r["read_ns"]) for r in IO if r["file"] == f) / 1e6, 3),
                 fl(st.fmean(int(r["write_ns"]) for r in IO if r["file"] == f) / 1e6, 3)] for f in sorted({r["file"] for r in IO}, key=lambda f: next(int(r["plaintext_bytes"]) for r in IO if r["file"] == f))])
sizes = CMP["ciphertext_size_by_plaintext_length"]; L = ["0", "1", "15", "16", "17", "31", "32", "1000"]
size_tbl = table(["Plaintext length (B)"] + L, [[m] + [sizes[m][n] for n in L] for m in sizes])
flip = CMP["bit_flip_in_ciphertext_block_2"]
flip_tbl = table(["Mode", "Result of flipping 1 ciphertext bit in block 2", "Wrong plaintext bits per block (blocks 0-9)"],
                 [[m, v["result"], str(v.get("wrong_bits_per_plaintext_block", "-"))] for m, v in flip.items()])
fresh = CMP["same_key_fresh_random_iv_twice"]
dups = CMP["repeated_block_plaintext_duplicate_ciphertext_blocks_of_8"]
pair = CMP["pairwise_bit_difference_fraction"]
pair_lo, pair_hi = min(pair.values()), max(pair.values())
same_first = [k for k, v in CMP["pairwise_first_block_identical"].items() if v]

# ---- data-derived statements
def ratio(f, a, b, op):  # mean time a / mean time b
    return float(g(f, a, op)["mean_s"]) / float(g(f, b, op)["mean_s"])
def ci_separated(f, a, b, op):
    x, y = g(f, a, op), g(f, b, op)
    return abs(float(x["mean_s"]) - float(y["mean_s"])) > float(x["ci95_halfwidth_s"]) + float(y["ci95_halfwidth_s"])
F10 = "random_10MiB.bin"; F1 = "random_1MiB.bin"
ctr_fastest_sizes = [lab[f] for f in sweep if min(AES4, key=lambda a: float(g(f, a, "encrypt")["mean_s"])) == "AES-CTR"]
cbc_dec_faster = [lab[f] for f in sweep if float(g(f, "AES-CBC", "decrypt")["mean_s"]) < float(g(f, "AES-CBC", "encrypt")["mean_s"]) and ci_separated(f, "AES-CBC", "AES-CBC", "encrypt") or
                  float(g(f, "AES-CBC", "decrypt")["mean_s"]) < 0.8 * float(g(f, "AES-CBC", "encrypt")["mean_s"])]
des_ratio = ratio(F10, "DES-CBC", "AES-CBC", "encrypt")
cv_vals = [float(r["cv_percent"]) for r in S if r["algorithm"] in AES4 and r["plaintext_bytes"] in ("1048576", "10485760")]
tests_log = (OUT / "test_results.txt").read_text(); ran = re.search(r"Ran (\d+) tests", tests_log).group(1); okline = "OK" if re.search(r"^OK", tests_log, re.M) else "FAILED"
loader = unittest.TestLoader(); per_mod = {m: loader.loadTestsFromName(f"tests.{m}").countTestCases() for m in ("test_crypto", "test_webapp", "test_benchmark")}
nfail = 0 if okline == "OK" else "see log"
envtbl = table(["Item", "Value"], [["Python", f"{ENV['python']} ({ENV['python_impl']})"], ["cryptography", ENV["cryptography"]], ["OpenSSL (backend)", ENV["openssl"]], ["OS", ENV["os"]],
                                   ["Processor", ENV["processor"]], ["Logical CPUs visible", ENV["logical_cpus"]], ["CPU reports AES instructions", ENV["cpu_reports_aes_instructions"]],
                                   ["Timer", f"time.perf_counter_ns (resolution {ENV['perf_counter_resolution_s']} s, monotonic={ENV['perf_counter_monotonic']})"],
                                   ["Trials / warm-up", f"{ENV['trials']} measured / {ENV['warmup']} discarded per file x algorithm x operation"],
                                   ["App-download trials", f"{ENV['app_download_trials']} per file x algorithm"], ["Run started / finished (UTC)", f"{ENV['started_utc']} / {ENV['finished_utc']}"],
                                   ["Timed region", ENV["timed_region"]]])

md = f"""---
title: "Secure Private Data Vault: AES / RC4 / DES file storage and AES-mode benchmark"
---

# 1. Title and assignment information

**Course / assignment:** Information Security, Assignment 1 (group of four)  
**Group members:** *[Name 1 – Student ID]*, *[Name 2 – Student ID]*, *[Name 3 – Student ID]*, *[Name 4 – Student ID]*  
**Lecturer / submission date:** *[to be filled in]*  
**Repository contents:** Flask application, `vault_crypto/` cipher module, `benchmark/`, `tests/`, this report.

# 2. Objectives and requirements

The assignment slides require a web application that (a) stores users' private data in a database, taking GDPR / UU PDP as the reference for what is private;
(b) stores an ID-card image, PDF/DOC/XLS files and video files; (c) encrypts all stored data with AES, RC4 and DES; (d) lets users retrieve their decrypted data;
and (e) requires a username/password. The second slide adds: use a **non-ECB block-cipher mode** (CBC, CFB, OFB or CTR), any cryptography library, a bug-free program,
an analysis of running time and ciphertext differences between the ciphers (downloading the data several times and measuring), a short report, and justification of all decisions.
This project covers all four modes (plus AES-GCM as an extra) and keeps RC4 and DES as the assignment demands, labelled obsolete.

# 3. System architecture and technology stack

| Layer | Choice | Why |
|---|---|---|
| Web framework | Flask (application factory in `app.py`) | Already used by the original project; small and easy to audit. |
| Database | SQLite via stdlib `sqlite3` | Original used Flask-SQLAlchemy; replaced by the stdlib module because it needs no extra dependency, uses parameterised SQL, and BLOB columns hold the ciphertext. |
| Cryptography | `cryptography` (pyca) {ENV['cryptography']} on OpenSSL | Maintained, exposes CBC/CFB/OFB/CTR/GCM uniformly, correct PKCS#7, hardware AES where available. The original used PyCryptodome; both are acceptable under the slide. |
| Password hashing | Werkzeug `generate_password_hash` | Salted, adaptive (scrypt by default in the installed version); same call as the original. |
| UI | Original Bootstrap templates, extended | Preserved look; added CSRF fields, algorithm choices, delete, metadata. |
| Tests | stdlib `unittest` (pytest-compatible) | `pytest` was not installable in the offline build environment. |

Request flow: browser → Flask route (session + CSRF check) → `uploads.validate_upload` → `vault_crypto.encrypt_bytes` → SQLite BLOB.
Download: ownership-scoped SQL lookup → `decrypt_bytes` (verify, then decrypt) → bytes streamed from memory to the browser.

# 4. Database design and storage decisions

**Decision:** encrypted bytes are stored **inside SQLite** (`BLOB`), not on the file system. The original stored JSON envelopes under `ciphertexts/` and kept only a path in the DB,
which weakens the claim "stored in a database" and also created path-handling risks. Table `encrypted_files` holds: `user_id` (foreign key, ownership), `original_filename`, `category`
(`id_card`/`document`/`video`), `mime_type`, `algorithm` (e.g. `AES-CBC`), `kdf`, `kdf_iterations`, `salt`, `iv`, `mac`, `plaintext_size`, `ciphertext_size`, `ciphertext`, `uploaded_at`, `group_id`.
`users` holds only `username`, the password hash and the creation time. No plaintext file content is stored or written to disk (the original wrote decrypted files into `uploads/`).

**Trade-off:** SQLite BLOBs are simple and transactional, but a whole file is held in memory while processing, so the default limit is 100 MB (`MAX_UPLOAD_MB`). Multi-gigabyte video would need chunked/streaming encryption
or external object storage; this is a documented limitation. **Needs lecturer confirmation:** whether "stored in a database" accepts ciphertext as BLOB (what we did) or only a storage reference.
Filenames, categories and sizes are plaintext metadata (they can themselves be personal data); encrypting them is future work.

**Privacy classification.** GDPR Art. 4(1) defines personal data broadly; Art. 9 adds special categories (e.g. health data, biometric data used to uniquely identify a person). UU PDP No. 27/2022 Art. 4 distinguishes
*specific* personal data (health, biometric, genetic, criminal records, children's data, personal financial data) from *general* personal data (full name, gender, nationality, religion, marital status, and data combined to identify a person).
An ID-card image contains general identifiers and a facial photo and should be treated as high-risk; documents and videos may contain any category. The app therefore treats **every upload as sensitive**, minimises what it stores about the user (no e-mail, no real name field), and lets the user delete files.

# 5. Authentication and authorization

* Registration: username `[A-Za-z0-9_.-]{{3,32}}` (case-insensitive unique), password ≥ 8 characters; stored with Werkzeug salted hashing. Login uses a constant-work check for unknown users and a per-(username, IP) throttle (5 failures / 5 min → HTTP 429).
* Sessions: `SECRET_KEY` is **required from the environment** (the original generated a random key at each start, invalidating sessions and breaking multi-worker use); cookies are `HttpOnly`, `SameSite=Lax`, `Secure` by default (set `SESSION_COOKIE_SECURE=0` only for plain-http localhost), 30-minute lifetime; the session is replaced on login.
* CSRF: every state-changing request (including logout, which is now POST) must carry a per-session token compared with `hmac.compare_digest`.
* Authorization: every file query is `WHERE id = ? AND user_id = ?`; another user's file simply does not exist (HTTP 404, no enumeration). This applies to download/decrypt, delete and the metadata endpoint (`/files/<id>/meta`, which never returns key material or ciphertext).
* Hardening: `nosniff`, `X-Frame-Options: DENY`, CSP, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` for authenticated pages; generic error pages (no stack traces); `debug=False`.

# 6. Encryption and decryption workflows

**Upload.** Validate (category, extension whitelist, declared MIME, magic bytes, non-empty, size limit, sanitised filename) → derive keys → encrypt → store.
**Key schedule.** `PBKDF2-HMAC-SHA256(password, random 16-byte salt, {600000} iterations) → 32-byte master → HKDF-Expand` with distinct labels gives an **encryption key** (32 B; 8 B for DES) and a separate **MAC key**.
Salt (per file), IV/nonce (per encryption) are random from `os.urandom`, stored beside the ciphertext, and are public values. The per-file password is chosen by the user at upload time and is never stored.
**Integrity.** AES-CBC/CFB/OFB/CTR, DES and RC4 give confidentiality only, so the envelope adds **encrypt-then-MAC**: HMAC-SHA256 over a length-prefixed header (algorithm, iterations, salt, IV) and the ciphertext; it is verified in constant time **before** any decryption. AES-GCM authenticates itself (header as AAD).
**Download.** Ownership check → verify → decrypt → compare length with stored `plaintext_size` → stream. A wrong password, a flipped bit, truncated data or altered metadata all produce the same generic message and **no file**. This fixes the original behaviour, in which CBC/RC4 could return corrupted plaintext as a "successful" download, and its `pkcs7unpad` accepted any padding byte.

# 7. AES, RC4 and DES implementation decisions

| Algorithm | Implementation | Notes |
|---|---|---|
| AES-256-CBC (app default) | PKCS#7 via the library's padder/unpadder | Non-ECB mode required by the slide. |
| AES-256-CFB (128-bit segments), OFB, CTR | no padding (stream-like) | CTR uses a random 16-byte initial counter block; never reuse key+nonce. |
| AES-256-GCM | 12-byte nonce, 16-byte tag | Extra, modern, authenticated option. |
| DES-CBC | 3DES primitive with an 8-byte key (K1=K2=K3), identical to single DES; PKCS#7 | The library no longer exposes single DES. **56-bit key: brute-forceable; 64-bit blocks.** |
| RC4 | `ARC4` with a 32-byte derived key | A **stream cipher**, not a block-cipher mode; biased keystream, prohibited in TLS (RFC 7465). |

RC4 and DES are included **only** to satisfy the assignment and are labelled as obsolete in the UI. They must not protect real personal data. For the slide's "encrypted with all of these algorithms" the user can choose
one algorithm per file or **ALL**, which stores three independent encrypted copies (AES-CBC, DES-CBC, RC4). Alternative readings (e.g. layered encryption) exist: **confirm with the lecturer**.

# 8. AES mode benchmarking methodology

*Library justification:* the same `cryptography`/OpenSSL code path is used by the app and the benchmark (`vault_crypto.raw_encrypt/raw_decrypt`), so results describe the shipped implementation.
*Inputs (synthetic, deterministic, no personal data; regenerated by `benchmark/generate_fixtures.py`, hashes in `MANIFEST.json`):* random binary at 1 KiB, 64 KiB, 1 MiB, 10 MiB, 50 MiB; 1 MiB seeded text; a 1024x768 PNG; a 200-page PDF built by hand; a 150-frame MJPEG AVI (OpenCV). Every algorithm receives byte-identical plaintext.
*Fairness:* same 256-bit key for all AES modes; fresh random IV/nonce each trial generated **outside** the timer; warm-up runs discarded; algorithm order **shuffled each trial** to spread drift and noise evenly; GC disabled inside timed regions;
correctness (`decrypt(encrypt(x)) == x`) asserted after every trial outside the timer, so the benchmark would abort on any mismatch.
*Timer & regions:* `time.perf_counter_ns` (monotonic). Encryption and decryption are timed **separately** around cipher construction + update + finalisation (+ PKCS#7 pad/unpad for CBC/DES). File read/write is measured separately (Section 10.3), and the assignment's "download" is also measured end-to-end through the Flask app (Section 10.4).
*Statistics:* per configuration n = {ENV['trials']}: mean, median, sample standard deviation, min, max, coefficient of variation, 95 % CI half-width (1.96·SD/√n), and throughput in MiB/s from the mean (and median) time.
*Why {ENV['trials']} trials + {ENV['warmup']} warm-ups:* a conventional sample size for the central-limit approximation that keeps the whole run to a few minutes; timings here are noisy (see limits), so more trials would help but cost time. Configurable via `--trials`, `--warmup`.
*Modes benchmarked:* AES-CBC, CFB, OFB, CTR (required), AES-GCM (extra AEAD), and DES-CBC and RC4 as **reference-only legacy** rows (RC4 is not a block-cipher mode and is not compared as one).

# 9. Test environment and experimental parameters

{envtbl}

Limits: the sandbox is a shared virtual machine exposing **one** logical CPU, so background noise is likely (CV of required-mode timings at 1 and 10 MiB ranged {min(cv_vals):.0f} % – {max(cv_vals):.0f} %); a few runs show large outliers at 64 KiB. Results are specific to this machine and a single run, and absolute numbers will differ elsewhere. OpenSSL AES-NI usage is reported by the CPU flags but was not independently verified.

# 10. Measured performance results

All numbers below are produced by `benchmark/run_benchmark.py` and read from `benchmark/results/*.csv` by this report generator. Raw trials: `raw_results.csv` ({len(rd(R/'raw_results.csv'))} rows).

## 10.1 Cipher-only time at 10 MiB and 1 MiB

**10 MiB random data**

{stat_table(F10)}

**1 MiB random data**

{stat_table(F1)}

## 10.2 Throughput versus input size (mean MiB/s)

*Encryption*

{sweep_table("encrypt")}

*Decryption*

{sweep_table("decrypt")}

![Throughput versus size](../benchmark/graphs/fig1_throughput_vs_size.png)

![Mean time at 10 MiB with 95 % CI](../benchmark/graphs/fig2_time_10MiB.png)

![Distribution of individual trials, 10 MiB](../benchmark/graphs/fig3_trial_distribution_10MiB.png)

**By data type** (mean encryption throughput; synthetic stand-ins for text, image, PDF and video):

{type_tbl}

![Throughput by data type](../benchmark/graphs/fig4_data_types.png)

## 10.3 File I/O measured separately

Plain `read_bytes()` and `write_bytes()` on the same inputs ({ENV['trials']} trials, page-cache effects included, so these are optimistic):

{io_tbl}

## 10.4 End-to-end web download through the Flask app

`POST /decrypt/<id>` through the real application with the production setting of {KDF['iterations']:,} PBKDF2 iterations ({ENV['app_download_trials']} downloads per cell; each response was verified byte-for-byte):

{app_tbl}

![End-to-end download](../benchmark/graphs/fig5_app_download.png)

The password KDF alone, measured separately ({KDF['trials']} runs), took a mean of **{KDF['mean_ms']:.0f} ms** (median {KDF['median_ms']:.0f}, SD {KDF['stdev_ms']:.0f}), while all end-to-end downloads had a median of {st.median(app_all):.0f} ms (range {min(app_all):.0f}–{max(app_all):.0f} ms).
So for files of the sizes tested here the download latency is **dominated by the KDF, which is identical for every algorithm**; differences between the AES modes and RC4 in this table are mostly within noise. DES-CBC is visibly slower for the larger files (e.g. the PNG and AVI rows), where its slow cipher speed is no longer hidden by the KDF.

## 10.5 Observations (what the data support)

* AES-CTR had the lowest mean encryption time among the four required modes at: {", ".join(ctr_fastest_sizes) or "no tested size"}. At 10 MiB its mean encryption time was {ratio(F10,'AES-CTR','AES-CBC','encrypt'):.2f}x that of CBC, {ratio(F10,'AES-CTR','AES-CFB','encrypt'):.2f}x CFB and {ratio(F10,'AES-CTR','AES-OFB','encrypt'):.2f}x OFB (95 % CIs {'do not overlap' if ci_separated(F10,'AES-CTR','AES-CBC','encrypt') else 'overlap'} against CBC).
* CBC encryption cannot be parallelised (each block depends on the previous ciphertext block) whereas CBC decryption can; at 1 MiB CBC decryption took {ratio(F1,'AES-CBC','AES-CBC','decrypt')*float(g(F1,'AES-CBC','decrypt')['mean_s'])/float(g(F1,'AES-CBC','encrypt')['mean_s']):.2f}x its encryption time, and at 10 MiB {float(g(F10,'AES-CBC','decrypt')['mean_s'])/float(g(F10,'AES-CBC','encrypt')['mean_s']):.2f}x.
* OFB keystream generation is sequential in both directions, and CFB decryption (which could be parallelised in principle) was not observed to be faster than CFB encryption here; their decryption/encryption time ratios at 10 MiB were close to 1 (CFB {float(g(F10,'AES-CFB','decrypt')['mean_s'])/float(g(F10,'AES-CFB','encrypt')['mean_s']):.2f}x, OFB {float(g(F10,'AES-OFB','decrypt')['mean_s'])/float(g(F10,'AES-OFB','encrypt')['mean_s']):.2f}x decrypt/encrypt).
* AES-GCM, which also authenticates, was as fast as or faster than CBC/CFB/OFB here ({ratio(F10,'AES-GCM','AES-CBC','encrypt'):.2f}x CBC at 10 MiB, encryption); a stream-style mode with hardware support can be cheaper than a mode without integrity protection, so speed alone says little about security.
* DES-CBC was about **{des_ratio:.0f}x slower** than AES-CBC at 10 MiB (software 3DES-based path, no hardware acceleration) and, from 1 MiB upward, RC4 was slower than every AES mode tested on this machine (it was the fastest row only at 1 KiB, where setup cost dominates): "old and simple" did not mean "fast".
* Small inputs (1 KiB) are dominated by per-call setup cost: the four required modes' mean encryption times were all between {min(ms(g('random_1KiB.bin',a,'encrypt'),'mean_s') for a in AES4)*1000:.0f} and {max(ms(g('random_1KiB.bin',a,'encrypt'),'mean_s') for a in AES4)*1000:.0f} microseconds with SDs of 10–18 µs, so they are not reliably distinguishable there. Throughput peaked around 1 MiB and fell at 10–50 MiB; a likely (untested) cause is cache/memory effects and allocation of large buffers.
* Throughput by data type did not follow a consistent ordering by content type. For one mode it still varied by up to about a factor of two (AES-GCM: {min(float(g(k[0],'AES-GCM','encrypt')['mean_throughput_MiBps']) for k in kinds[:4]):.0f}–{max(float(g(k[0],'AES-GCM','encrypt')['mean_throughput_MiBps']) for k in kinds[:4]):.0f} MiB/s across text, PNG, PDF and AVI), but those files also differ in size (0.4–1.6 MiB) and the machine is noisy, so this experiment cannot attribute differences to the content type. Block-cipher speed is not expected to depend on plaintext content.

# 11. Ciphertext comparison and technical interpretation

Lab experiments use a **fixed lab key and IV only for reproducibility** (`benchmark/ciphertext_comparison.py`); they must never be reused for real data. Plaintext: first 4096 bytes of the text fixture.

**(a)** **Different modes give different ciphertexts.** Each mode combines key, IV and plaintext differently (CBC XORs the previous ciphertext block before encrypting; CFB/OFB/CTR XOR plaintext with a keystream; GCM is CTR plus a tag). With the same key and IV, pairs of ciphertexts differed in {pair_lo*100:.1f} %–{pair_hi*100:.1f} % of bits (≈ 50 %, as for unrelated random strings).
One legitimate coincidence: with the *same* IV, CFB, OFB and CTR produce an **identical first block** ({", ".join(same_first)}), because each XORs plaintext block 1 with E_K(IV); they diverge from block 2 on. (This is also why reusing an IV is dangerous.)

**(b)** **Randomness controls reproducibility.** With identical key *and* IV, every mode was deterministic (all `True` in `ciphertext_comparison.json`). With a fresh random IV, ciphertexts of the same plaintext differed ({", ".join(f"{m}: {v['bit_difference_fraction']*100:.1f}% bits" for m, v in fresh.items())}). In the app the salt and IV are also fresh per file, so even the same file under the same password gives different stored bytes; an observer cannot see that two files are equal. Reproducibility therefore requires fixing key and IV, which is only acceptable in experiments.

**(c)** **Size and padding.**

{size_tbl}

CBC/DES pad with PKCS#7: 1–16 extra bytes (a full extra block when the length is already a multiple of 16; even empty input becomes one block). CFB/OFB/CTR/RC4 keep the exact length; GCM adds a 16-byte tag. The app additionally stores a 16-byte salt, an IV and (except GCM) a 32-byte HMAC per file.

**(d)** **Why ECB is excluded.** Eight identical 16-byte plaintext blocks produced duplicate ciphertext blocks only under ECB (demonstration only): {", ".join(f"{k}: {v}" for k, v in dups.items())}. Equal plaintext blocks leak structure in ECB.

**(e)** **Bit-error behaviour (raw, unauthenticated modes).**

{flip_tbl}

CTR and OFB: only the flipped bit changes (an attacker can flip chosen plaintext bits: malleability). CBC: the whole corresponding block is garbled and one bit flips in the next block. CFB: the corresponding bit flips and the following block is garbled. AES-GCM rejects the data. In the app the HMAC / GCM tag catches all of these **before** any plaintext is released, so error propagation is only visible in the raw modes.

**(f)** **Limits of speed-only comparisons.** Speed depends on the library, CPU instructions, buffer sizes and noise; it ignores security properties: none of CBC/CFB/OFB/CTR provides integrity on its own, CBC padding can enable padding-oracle attacks if error messages differ (the app uses one generic error and verifies a MAC first), CTR/OFB/GCM are catastrophic under nonce reuse, and CFB/CBC leak IV-related structure when IVs are predictable. A mode must be chosen for its security and fitness first; AES-GCM (or encrypt-then-MAC) is the modern choice.

# 12. Functional testing results

Executed with `python -m unittest discover -s tests -t . -v` on the environment of Section 9; full log in `report/test_results.txt`.

**Result: {ran} tests run, {okline}.** (`test_crypto`: {per_mod['test_crypto']}, `test_webapp`: {per_mod['test_webapp']}, `test_benchmark`: {per_mod['test_benchmark']}; failures: {nfail}.)

| # | Required area | Where tested |
|---|---|---|
| 1–2 | Registration, login, invalid logins, throttling, logout | `test_webapp.Auth` |
| 3–5 | Upload + encryption with AES (all modes), RC4, DES, and `ALL` | `UploadDownload.test_each_algorithm_roundtrip_byte_for_byte`, `test_all_three_required_algorithms_option` |
| 6 | Byte-for-byte integrity | same tests (`assertEqual(r.data, data)`) |
| 7 | Wrong password | `UploadDownload.test_wrong_password_returns_no_file`, `test_crypto.Tamper` |
| 8 | Empty files, arbitrary binary | web: empty rejected by policy; crypto: sizes 0…100 003 B for every algorithm (`RoundTrip`) |
| 9 | Image, document, video | `test_all_file_types_and_categories` (png, jpg, jpeg, pdf, doc, docx, xls, xlsx, mp4, mov, avi, webm, mkv), `test_large_video_like_upload` |
| 10 | Unsupported types, oversized | `test_unsupported_and_mismatched_types`, `test_oversized_upload` |
| 11 | Corrupted / tampered ciphertext | `Tampering.*`, `test_crypto.Tamper.*` |
| 12 | Missing / invalid metadata | `test_invalid_or_missing_metadata`, `test_null_metadata_blocked_by_schema`, `Tamper.test_invalid_metadata` |
| 13 | Unauthorised access | `Authorization.*` |
| 14 | Path traversal | `PathTraversal.*` |
| 15 | Persistence / restart | `Persistence.test_survives_application_restart` |
| 16–17 | Every required AES mode, varied sizes incl. empty | `test_crypto.KnownAnswer` (NIST SP 800-38A vectors), `RoundTrip`, `test_benchmark.Reproducibility` |
| 18 | Benchmark output completeness / reproducibility | `test_benchmark.Runner`, `Fixtures`, `Reproducibility` |

Bugs found and fixed during this work include: random per-start `SECRET_KEY`; `debug=True`; plaintext written to `uploads/` with the user-controlled name (path traversal / overwrite); padding never validated and no integrity check, so tampered or wrong-password CBC/RC4 data could be returned as a "successful" download; GET logout (CSRF); no upload or password validation; and during testing, a template bug that displayed blank filenames and a sanitiser that left `..` inside names.
The tests do **not** cover a real browser, TLS, concurrency, or very large (≥ 1 GB) files. Not executed: `pytest` itself (not installable offline; the suite is plain `unittest`, which `pytest` also collects).

# 13. Security limitations and ethical considerations

* **Not production-secure and not legally certified.** Technical controls help with GDPR Art. 5 principles (integrity/confidentiality, data minimisation, storage limitation via deletion), Art. 25/32 (security by design, appropriate measures) and UU PDP duties to protect personal data, but compliance also needs lawful basis and consent management, privacy notices, retention policy, breach procedures, records of processing, access logging, data-subject rights tooling (e.g. account erasure/export), and for GDPR possibly a DPIA. None of these are implemented beyond what is listed here; no legal compliance is claimed.
* DES and RC4 are broken (56-bit keys; biased keystream; 64-bit block issues such as Sweet32). They are present only because the assignment requires them; do not use them for real data.
* Security depends on the **strength of the per-file password** (PBKDF2 slows guessing but cannot save "12345678"); there is no recovery: a forgotten password means permanent data loss.
* The server sees the file password and plaintext during upload/download (server-side encryption). End-to-end/client-side encryption would remove that trust.
* Plaintext metadata (name, size, time, category); login throttle held in process memory; no 2FA; CDN assets for Bootstrap/fonts; whole-file in-memory processing; magic-byte checks are not malware scanning.
* Ethics: use only synthetic or consented data when testing. The repository contains no real IDs, documents or credentials; benchmark fixtures are synthetic.

# 14. Justification of major development decisions

| Decision | Reason |
|---|---|
| Rebuild on `cryptography`, `sqlite3` | Required packages (PyCryptodome, Flask-SQLAlchemy) could not be installed offline; stdlib + one well-known library means fewer dependencies and a smaller attack surface. |
| Ciphertext as SQLite BLOB | Literally "stored in a database"; transactional; no filesystem paths to attack. Cost: memory use and size limit. |
| Encrypt-then-MAC, HKDF-separated keys | Unauthenticated modes return garbage or enable attacks; the slide demands a bug-free program, so tampering must never yield "successful" output. |
| PBKDF2 600 000 iterations (kept from original) | This matches the figure OWASP's Password Storage Cheat Sheet gave for PBKDF2-HMAC-SHA256 when last checked (re-verify the current value before deployment); ≈ {KDF['mean_ms']:.0f} ms here. Iteration count stored per file for future migration. |
| AES-CBC default for the app | Satisfies the "non-ECB mode" requirement and was the original design; CFB/OFB/CTR/GCM selectable. GCM recommended for real use. |
| `ALL` option | Reasonable reading of "encrypted with all of these algorithms"; flagged for lecturer confirmation. |
| Generic error messages, 404 for foreign files | Avoid oracles and enumeration. |
| Separate cipher-only, I/O and end-to-end timings | The slide says "download multiple times", which includes KDF/DB/HTTP costs that would otherwise mask cipher differences. |
| Synthetic, seeded fixtures | Reproducible, no personal data, portable. |

# 15. Conclusion

The application stores ID-card images, documents and videos as ciphertext in the database, encrypted per file with AES (CBC, CFB, OFB, CTR or GCM), DES or RC4, returns them byte-for-byte after successful verification, and
isolates each user's data. In the measurements on this machine, AES-CTR (and the CTR-based GCM) were the fastest at sizes from 1 MiB, CBC encryption was slower than CBC decryption at 1 and 10 MiB, CFB and OFB decryption was no faster than their encryption, and DES was
roughly {des_ratio:.0f} times slower than AES-CBC at 10 MiB. Ciphertexts differ between modes and between runs whenever the IV, nonce or salt differ, CBC pads and the stream-like modes do not, and bit errors propagate differently in each mode, which is a security consideration that a pure speed ranking ignores.
For real end-to-end download times, the password KDF dominated all algorithm differences for the file sizes tested. Limitations: single noisy machine, single run, synthetic data, ambiguity in two assignment requirements (to be confirmed), and non-production scope.

# 16. References

1. NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques* (CBC, CFB, OFB, CTR). https://csrc.nist.gov/pubs/sp/800/38/a/final
2. NIST SP 800-38D, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*. https://csrc.nist.gov/pubs/sp/800/38/d/final
3. NIST FIPS 197, *Advanced Encryption Standard (AES)*. https://csrc.nist.gov/pubs/fips/197/final
4. RFC 7465, *Prohibiting RC4 Cipher Suites*. https://datatracker.ietf.org/doc/html/rfc7465 ; RFC 6229, *Test Vectors for the Stream Cipher RC4*. https://datatracker.ietf.org/doc/html/rfc6229
5. RFC 8018, *PKCS #5: Password-Based Cryptography Specification v2.1* (PBKDF2). https://datatracker.ietf.org/doc/html/rfc8018 ; RFC 5869, *HKDF*. https://datatracker.ietf.org/doc/html/rfc5869
6. pyca/cryptography documentation. https://cryptography.io/en/latest/
7. OWASP Cheat Sheet Series: Password Storage; Cross-Site Request Forgery Prevention. https://cheatsheetseries.owasp.org/
8. Flask documentation. https://flask.palletsprojects.com/ ; Werkzeug security utilities. https://werkzeug.palletsprojects.com/
9. SQLite documentation (data types, limits). https://www.sqlite.org/limits.html
10. Regulation (EU) 2016/679 (GDPR), Arts. 4, 5, 9, 25, 32. https://eur-lex.europa.eu/eli/reg/2016/679/oj
11. Undang-Undang Republik Indonesia Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi, Art. 4 (official text, JDIH Kemenkeu): https://jdih.kemenkeu.go.id/download/46c17b53-4a45-411c-9b76-c6799e5769fc/UU_Nomor_27_Tahun_2022 Perlindungan Data Pribadi.pdf
12. Bhargavan, K., Leurent, G., *On the Practical (In-)Security of 64-bit Block Ciphers (Sweet32)*, ACM CCS 2016. https://sweet32.info/
13. Bellare, M., Namprempre, C., *Authenticated Encryption: Relations among Notions and Analysis of the Generic Composition Paradigm*, ASIACRYPT 2000.

*URLs were not all re-fetched in the build environment; the UU PDP Art. 4 categories were checked against secondary summaries and the official-text search result, so confirm article wording against the official text before submission.*
"""
(OUT / "report.md").write_text(md, encoding="utf-8")
print("wrote report.md")

# ---- PDF (pandoc -> docx -> LibreOffice), best effort
if shutil.which("pandoc") and shutil.which("soffice"):
    try:
        subprocess.run(["pandoc", "report.md", "-o", "report.docx", "--resource-path=.", "-f", "markdown+pipe_tables"], cwd=OUT, check=True)
        subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "report.docx"], cwd=OUT, check=True, capture_output=True, timeout=180)
        (OUT / "report.docx").unlink(missing_ok=True); print("wrote report.pdf")
    except Exception as e:
        print("PDF generation failed:", e)
else:
    print("pandoc/soffice not available: PDF skipped (see README)")
