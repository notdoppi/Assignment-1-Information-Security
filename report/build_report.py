"""Build report/report.md and report/report.pdf from current benchmark results.

Expected run from any directory:
    python report/build_report.py
The report only compares AES-GCM, DES-CBC, and RC4.
"""
from __future__ import annotations

import csv
import json
import statistics as stats
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmark" / "results"
GRAPHS = ROOT / "benchmark" / "graphs"
REPORT_DIR = ROOT / "report"
ALGORITHMS = ("AES-GCM", "DES-CBC", "RC4")
DISPLAY = {
    "AES-GCM": "AES-256-GCM",
    "DES-CBC": "DES-CBC (legacy)",
    "RC4": "RC4 (legacy stream cipher)",
}


def read_csv(filename: str) -> list[dict[str, str]]:
    path = RESULTS / filename
    if not path.exists():
        return []
    with path.open("r", newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def read_json(filename: str) -> dict:
    path = RESULTS / filename
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def fmt(value: float, digits: int = 2) -> str:
    return f"{value:.{digits}f}"


def markdown_table(headers: list[str], rows: list[list[object]]) -> list[str]:
    result = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    result.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return result


def mean_ms(rows: list[dict[str, str]], field: str) -> float | None:
    vals = [float(row[field]) for row in rows if row.get(field)]
    return stats.fmean(vals) / 1_000_000 if vals else None


def build_markdown() -> str:
    summary = read_csv("summary.csv")
    raw = read_csv("raw_results.csv")
    app = read_csv("app_download_results.csv")
    io_rows = read_csv("io_results.csv")
    env = read_json("environment.json")
    kdf = read_json("kdf_timing.json")
    comparison = read_json("ciphertext_comparison.json")

    # Keep only the selected algorithms even if old CSV rows remain in the folder.
    summary = [row for row in summary if row.get("algorithm") in ALGORITHMS]
    raw = [row for row in raw if row.get("algorithm") in ALGORITHMS]
    app = [row for row in app if row.get("algorithm") in ALGORITHMS]
    files = sorted({row.get("file", "") for row in summary if row.get("file")})
    sizes = {row["file"]: int(row["plaintext_bytes"]) for row in summary if row.get("file") and row.get("plaintext_bytes")}

    lines = [
        "# Secure Personal Health Vault",
        "## Three-Algorithm Performance Evaluation",
        "",
        "## 1. Scope and objective",
        "This report compares three configurations: AES-256-GCM, DES-CBC, and RC4. AES-GCM is the recommended choice for protecting real vault data because it provides authenticated encryption. DES and RC4 are obsolete and are included only for academic comparison; they must not be used to protect real personal or health records.",
        "",
        "The benchmark measures the implementation configurations available in this project. AES-GCM includes its authentication tag. DES-CBC and RC4 use separate HMAC-SHA256 integrity protection in the application, so raw-cipher timing is not a comparison of identical security mechanisms. Application download timings include more than the cipher operation.",
        "",
        "## 2. Environment and methodology",
    ]
    env_rows = [
        ["Python", env.get("python", "not recorded") + (f" ({env.get('python_impl')})" if env.get("python_impl") else "")],
        ["Cryptography library", env.get("cryptography", "not recorded")],
        ["OpenSSL", env.get("openssl", "not recorded")],
        ["Operating system", env.get("os", "not recorded")],
        ["Processor", env.get("processor") or env.get("machine", "not recorded")],
        ["Logical CPUs visible", env.get("logical_cpus", "not recorded")],
        ["Measured trials", env.get("trials", "not recorded")],
        ["Warm-up runs", env.get("warmup", "not recorded")],
        ["Benchmark started (UTC)", env.get("started_utc", "not recorded")],
        ["Benchmark finished (UTC)", env.get("finished_utc", "not recorded")],
    ]
    lines += markdown_table(["Environment item", "Value"], env_rows)
    lines += [
        "",
        "The benchmark uses synthetic input files and measures encryption and decryption separately. Throughput is reported in MiB/s, where 1 MiB = 1,048,576 bytes. Timing results are machine- and workload-dependent; they should not be generalized to every computer or deployment.",
        "",
        "## 3. Mean performance on 10 MiB input",
        "",
    ]
    target_file = "random_10MiB.bin"
    target = [r for r in summary if r.get("file") == target_file]
    if target:
        rows = []
        for algorithm in ALGORITHMS:
            for operation in ("encrypt", "decrypt"):
                row = next((r for r in target if r.get("algorithm") == algorithm and r.get("op") == operation), None)
                if row:
                    rows.append([
                        DISPLAY[algorithm], operation,
                        fmt(float(row["mean_s"]) * 1000, 3),
                        fmt(float(row["stdev_s"]) * 1000, 3),
                        fmt(float(row["mean_throughput_MiBps"]), 2),
                        fmt(float(row["ci95_halfwidth_s"]) * 1000, 3),
                    ])
        lines += markdown_table(["Algorithm", "Operation", "Mean (ms)", "SD (ms)", "Mean throughput (MiB/s)", "95% CI half-width (ms)"], rows)
    else:
        lines.append("The current summary CSV does not contain random_10MiB.bin, so this table could not be populated. Run the benchmark to generate current measurements.")

    lines += ["", "## 4. Throughput across file sizes", ""]
    sweep_files = [f for f in ("random_1KiB.bin", "random_64KiB.bin", "random_1MiB.bin", "random_10MiB.bin", "random_50MiB.bin") if f in files]
    size_labels = {"random_1KiB.bin": "1 KiB", "random_64KiB.bin": "64 KiB", "random_1MiB.bin": "1 MiB", "random_10MiB.bin": "10 MiB", "random_50MiB.bin": "50 MiB"}
    for operation in ("encrypt", "decrypt"):
        lines += [f"### {operation.title()} throughput", ""]
        rows = []
        for algorithm in ALGORITHMS:
            cells: list[object] = [DISPLAY[algorithm]]
            for filename in sweep_files:
                row = next((r for r in summary if r.get("file") == filename and r.get("algorithm") == algorithm and r.get("op") == operation), None)
                cells.append(fmt(float(row["mean_throughput_MiBps"]), 2) if row else "—")
            rows.append(cells)
        lines += markdown_table(["Algorithm"] + [size_labels[f] for f in sweep_files], rows) if sweep_files else ["No standard random-binary size sweep was found in the summary CSV."]
        lines.append("")
    for graph, caption in [
        ("fig1_throughput_vs_size.png", "Throughput versus input size"),
        ("fig2_time_10MiB.png", "Mean operation time for 10 MiB input"),
        ("fig3_trial_distribution_10MiB.png", "Distribution of individual trials for 10 MiB input"),
        ("fig4_data_types.png", "Throughput by synthetic data type"),
    ]:
        if (GRAPHS / graph).exists():
            lines += [f"![{caption}](../benchmark/graphs/{graph})", ""]

    lines += ["## 5. End-to-end application download", ""]
    if app:
        app_files = sorted({r.get("file", "") for r in app if r.get("file")})
        app_table_rows = []
        for algorithm in ALGORITHMS:
            cells: list[object] = [DISPLAY[algorithm]]
            for filename in app_files:
                value = mean_ms([r for r in app if r.get("algorithm") == algorithm and r.get("file") == filename], "download_ns")
                cells.append(fmt(value, 2) if value is not None else "—")
            app_table_rows.append(cells)
        lines += markdown_table(["Algorithm"] + app_files, app_table_rows)
        lines += ["", "These timings include application-level work such as key derivation, database access, decryption, and response handling, depending on the benchmark harness. They should not be interpreted as raw cipher throughput.", ""]
        if (GRAPHS / "fig5_app_download.png").exists():
            lines += ["![End-to-end application download](../benchmark/graphs/fig5_app_download.png)", ""]
    else:
        lines += ["No application download measurements were found. If the assignment requires end-to-end measurements, rerun the benchmark and verify that `app_download_results.csv` is populated.", ""]

    lines += ["## 6. File I/O measurements", ""]
    if io_rows:
        io_files = sorted({r.get("file", "") for r in io_rows if r.get("file")}, key=lambda f: sizes.get(f, 0))
        io_table_rows = []
        for filename in io_files:
            matching = [r for r in io_rows if r.get("file") == filename]
            read = mean_ms(matching, "read_ns")
            write = mean_ms(matching, "write_ns")
            size = next((r.get("plaintext_bytes", "—") for r in matching), "—")
            io_table_rows.append([filename, size, fmt(read, 3) if read is not None else "—", fmt(write, 3) if write is not None else "—"])
        lines += markdown_table(["File", "Size (bytes)", "Mean read (ms)", "Mean write (ms)"], io_table_rows)
    else:
        lines.append("No file I/O results were found.")

    lines += ["", "## 7. Integrity and ciphertext observations", ""]
    flips = comparison.get("bit_flip_in_ciphertext_block_2", {})
    if flips:
        flip_rows = []
        for algorithm in ALGORITHMS:
            result = flips.get(algorithm)
            if result:
                flip_rows.append([DISPLAY[algorithm], result.get("result", "not recorded"), "Yes" if not result.get("plaintext_returned", True) else "No"])
        lines += markdown_table(["Algorithm", "Result after ciphertext bit flip", "Plaintext rejected"], flip_rows)
        lines.append("")
    sizes_data = comparison.get("ciphertext_size_by_plaintext_length", {})
    if sizes_data:
        lengths = [k for k in ("0", "1", "15", "16", "17", "31", "32", "1000") if any(k in values for values in sizes_data.values())]
        if lengths:
            size_rows = []
            for algorithm, mapping in sizes_data.items():
                if algorithm in ALGORITHMS:
                    size_rows.append([DISPLAY[algorithm]] + [mapping.get(length, "—") for length in lengths])
            if size_rows:
                lines += ["### Ciphertext sizes", ""]
                lines += markdown_table(["Algorithm"] + [f"Plaintext {length} B" for length in lengths], size_rows)
                lines.append("")

    lines += [
        "## 8. Interpretation and limitations",
        "- AES-GCM is the recommended choice for the vault because it provides confidentiality and integrity using authenticated encryption. Its 12-byte nonce must never be reused with the same key; the 16-byte authentication tag detects tampering.",
        "- DES is obsolete and its effective key strength is inadequate for modern security. RC4 is an obsolete stream cipher with known keystream biases. Both are included only for academic comparison.",
        "- The app uses a separate HMAC-SHA256 for DES-CBC and RC4, whereas AES-GCM has a built-in authentication tag. Raw benchmark timings do not include all application security overhead unless the benchmark explicitly measures the full application path.",
        "- Results depend on CPU, operating system, cryptography/OpenSSL versions, input size, system load, and number of trials. A single run is not a universal performance ranking.",
        "- Synthetic fixtures are not real patient data. The benchmark does not establish legal compliance or production readiness.",
    ]
    if kdf:
        lines += [f"- Separate KDF timing data: PBKDF2 iteration count {kdf.get('iterations', 'not recorded')}; mean {float(kdf.get('mean_ms', 0)):.2f} ms across {kdf.get('trials', 'not recorded')} trials. This value is contextual and is not added to raw cipher-only timings."]
    lines += ["", "## 9. Conclusion", "The benchmark compares AES-256-GCM, DES-CBC, and RC4 using the available measurements. Select AES-GCM for real vault data; the legacy algorithms are retained only to satisfy the academic comparison requirement. Discuss measured differences using the generated tables and graphs, while distinguishing raw cipher timing from application download latency.", "", "---", "Generated from the current files in `benchmark/results/`. Regenerate this report after the final benchmark run; do not submit filtered or stale results as fresh measurements.", ""]
    return "\n".join(lines)


def write_pdf(markdown: str) -> None:
    """Create a readable PDF with ReportLab if it is installed."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    except ImportError:
        print("ReportLab is not installed; Markdown report was written, PDF was skipped.")
        return

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=12))
    doc = SimpleDocTemplate(str(REPORT_DIR / "report.pdf"), pagesize=A4, rightMargin=40, leftMargin=40, topMargin=42, bottomMargin=42)
    story = []
    lines = markdown.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line == "---":
            story.append(Spacer(1, 6)); i += 1; continue
        if line.startswith("!["):
            # Keep image embedding optional; resolve known graph paths only.
            try:
                start = line.find("](") + 2
                rel = line[start:line.rfind(")")]
                image_path = (REPORT_DIR / rel).resolve()
                if image_path.exists() and image_path.is_file():
                    story.append(Image(str(image_path), width=460, height=230, kind="proportional"))
                    story.append(Spacer(1, 8))
            except Exception:
                pass
            i += 1; continue
        if line.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].startswith("|"):
                table_lines.append(lines[i]); i += 1
            parsed = []
            for item in table_lines:
                cells = [c.strip() for c in item.strip().strip("|").split("|")]
                if cells and all(set(c) <= set("-: ") for c in cells):
                    continue
                parsed.append([Paragraph(escape(c), styles["BodyText"]) for c in cells])
            if parsed:
                width = 515
                ncols = max(len(row) for row in parsed)
                col_widths = [width / ncols] * ncols
                story.append(Table(parsed, colWidths=col_widths, repeatRows=1, hAlign="LEFT", style=TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3")),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ])))
                story.append(Spacer(1, 8))
            continue
        if line.startswith("# "):
            story.append(Paragraph(escape(line[2:]), styles["ReportTitle"]))
        elif line.startswith("## "):
            story.append(Paragraph(escape(line[3:]), styles["Heading1"]))
        elif line.startswith("### "):
            story.append(Paragraph(escape(line[4:]), styles["Heading2"]))
        elif line.startswith("- "):
            story.append(Paragraph("• " + escape(line[2:]), styles["BodyText"]))
        else:
            story.append(Paragraph(escape(line), styles["BodyText"]))
        story.append(Spacer(1, 4))
        i += 1
    doc.build(story)
    print(f"Wrote {REPORT_DIR / 'report.pdf'}")


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    markdown = build_markdown()
    output = REPORT_DIR / "report.md"
    output.write_text(markdown, encoding="utf-8")
    print(f"Wrote {output}")
    write_pdf(markdown)


if __name__ == "__main__":
    main()
