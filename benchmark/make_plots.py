"""Generate report graphs from benchmark/results/*.csv (never from hard-coded numbers)."""
from __future__ import annotations
import argparse, csv
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ORDER = ["AES-CBC", "AES-CFB", "AES-OFB", "AES-CTR", "AES-GCM", "DES-CBC", "RC4"]
COLORS = {"AES-CBC": "#1f77b4", "AES-CFB": "#ff7f0e", "AES-OFB": "#2ca02c", "AES-CTR": "#d62728",
          "AES-GCM": "#9467bd", "DES-CBC": "#8c564b", "RC4": "#7f7f7f"}


def read(p): return list(csv.DictReader(open(p)))


def make(results: Path, outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True); made = []
    summ = read(results / "summary.csv"); raw = read(results / "raw_results.csv")
    sweep = {"random_1KiB.bin": 1024, "random_64KiB.bin": 65536, "random_1MiB.bin": 1 << 20,
             "random_10MiB.bin": 10 << 20, "random_50MiB.bin": 50 << 20}
    present = {r["file"] for r in summ}

    # 1. Throughput vs size (log-log), encrypt and decrypt
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2), sharey=True)
    for ax, op in zip(axes, ("encrypt", "decrypt")):
        for a in ORDER:
            pts = sorted((int(r["plaintext_bytes"]), float(r["mean_throughput_MiBps"]), float(r["ci95_halfwidth_s"]), float(r["mean_s"]))
                         for r in summ if r["algorithm"] == a and r["op"] == op and r["file"] in sweep and r["file"] in present)
            if pts: ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=a, color=COLORS[a], ls="--" if a in ("DES-CBC", "RC4") else "-")
        ax.set_xscale("log"); ax.set_yscale("log"); ax.set_xlabel("Input size (bytes)"); ax.set_title(f"{op.capitalize()}ion throughput" if op == "encrypt" else "Decryption throughput")
        ax.grid(True, which="both", alpha=.3)
    axes[0].set_ylabel("Mean throughput (MiB/s)"); axes[1].legend(fontsize=8)
    fig.suptitle("Throughput vs input size (random data, mean of trials)"); fig.tight_layout()
    p = outdir / "fig1_throughput_vs_size.png"; fig.savefig(p, dpi=150); plt.close(fig); made.append(p)

    # 2. Time at 10 MiB with 95% CI error bars
    fn = "random_10MiB.bin"
    if fn in present:
        fig, ax = plt.subplots(figsize=(9, 4.2)); w = .38
        for i, op in enumerate(("encrypt", "decrypt")):
            vals = {r["algorithm"]: (float(r["mean_s"]) * 1000, float(r["ci95_halfwidth_s"]) * 1000) for r in summ if r["file"] == fn and r["op"] == op}
            xs = [j + (i - .5) * w for j in range(len(ORDER))]
            ax.bar(xs, [vals[a][0] for a in ORDER], w, yerr=[vals[a][1] for a in ORDER], capsize=3, label=op, alpha=.85)
        ax.set_xticks(range(len(ORDER))); ax.set_xticklabels(ORDER, rotation=20); ax.set_ylabel("Mean time (ms), 95% CI")
        ax.set_yscale("log"); ax.set_title("Mean processing time for a 10 MiB input"); ax.legend(); ax.grid(True, axis="y", alpha=.3)
        fig.tight_layout(); p = outdir / "fig2_time_10MiB.png"; fig.savefig(p, dpi=150); plt.close(fig); made.append(p)

        # 3. Box plot of individual trials (AES modes + GCM), 10 MiB
        fig, axes = plt.subplots(1, 2, figsize=(11, 4))
        for ax, op in zip(axes, ("encrypt", "decrypt")):
            ms = [a for a in ORDER if a.startswith("AES")]
            data = [[int(r["time_ns"]) / 1e6 for r in raw if r["file"] == fn and r["algorithm"] == a and r["op"] == op] for a in ms]
            ax.boxplot(data, tick_labels=ms, showfliers=True); ax.set_ylabel("Trial time (ms)"); ax.set_title(f"{op} - 10 MiB, individual trials"); ax.grid(True, axis="y", alpha=.3)
        fig.tight_layout(); p = outdir / "fig3_trial_distribution_10MiB.png"; fig.savefig(p, dpi=150); plt.close(fig); made.append(p)

    # 4. Data-type comparison (throughput, encrypt) across representative files
    kinds = [("text_1MiB.txt", "text 1 MiB"), ("image_synthetic.png", "image PNG"), ("document_synthetic.pdf", "PDF"),
             ("video_synthetic.avi", "video AVI"), ("random_1MiB.bin", "random 1 MiB")]
    kinds = [k for k in kinds if k[0] in present]
    if kinds:
        fig, ax = plt.subplots(figsize=(10, 4.2)); w = .8 / len(ORDER)
        for i, a in enumerate(ORDER):
            vals = []
            for f, _ in kinds:
                r = next(r for r in summ if r["file"] == f and r["algorithm"] == a and r["op"] == "encrypt"); vals.append(float(r["mean_throughput_MiBps"]))
            ax.bar([j + (i - len(ORDER) / 2 + .5) * w for j in range(len(kinds))], vals, w, label=a, color=COLORS[a])
        ax.set_xticks(range(len(kinds))); ax.set_xticklabels([f"{k[1]}" for k in kinds]); ax.set_yscale("log"); ax.set_ylabel("Mean encryption throughput (MiB/s)")
        ax.set_title("Encryption throughput by data type"); ax.legend(ncol=4, fontsize=8); ax.grid(True, axis="y", alpha=.3)
        fig.tight_layout(); p = outdir / "fig4_data_types.png"; fig.savefig(p, dpi=150); plt.close(fig); made.append(p)

    # 5. End-to-end download through the Flask app (includes PBKDF2, HMAC, DB, HTTP)
    ap = results / "app_download_results.csv"
    if ap.exists():
        import statistics as st
        rows = read(ap); files = sorted({r["file"] for r in rows})
        fig, ax = plt.subplots(figsize=(10, 4.2)); w = .8 / len(ORDER)
        for i, a in enumerate(ORDER):
            vals = [st.fmean(int(r["download_ns"]) for r in rows if r["file"] == f and r["algorithm"] == a) / 1e6 for f in files]
            ax.bar([j + (i - len(ORDER) / 2 + .5) * w for j in range(len(files))], vals, w, label=a, color=COLORS[a])
        ax.set_xticks(range(len(files))); ax.set_xticklabels(files, rotation=10); ax.set_ylabel("Mean download time (ms)")
        ax.set_title("End-to-end web download (POST /decrypt): KDF + DB read + verify + decrypt + response"); ax.legend(ncol=4, fontsize=8); ax.grid(True, axis="y", alpha=.3)
        fig.tight_layout(); p = outdir / "fig5_app_download.png"; fig.savefig(p, dpi=150); plt.close(fig); made.append(p)
    return made


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); root = Path(__file__).resolve().parent
    ap.add_argument("--results", default=str(root / "results")); ap.add_argument("--out", default=str(root / "graphs"))
    a = ap.parse_args()
    for p in make(Path(a.results), Path(a.out)): print("wrote", p)
