"""Tests for the benchmark component (small configuration so the suite stays fast)."""
import csv, json, os, shutil, tempfile, unittest
from pathlib import Path

from benchmark import ciphertext_comparison, generate_fixtures, make_plots, run_benchmark
from vault_crypto import ALGORITHMS, REQUIRED_ALGORITHMS, raw_decrypt, raw_encrypt

TRIALS, WARMUP = 4, 1
ONLY = ["random_1KiB.bin", "random_64KiB.bin", "text_1MiB.txt", "document_synthetic.pdf"]


class Fixtures(unittest.TestCase):
    def test_fixture_generation_is_reproducible(self):
        a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
        try:
            ma = generate_fixtures.generate(Path(a), include_50mib=False)
            mb = generate_fixtures.generate(Path(b), include_50mib=False)
            self.assertEqual(ma, mb)
            self.assertIn("random_1MiB.bin", ma)
        finally:
            shutil.rmtree(a); shutil.rmtree(b)


class Runner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp()); cls.fx = cls.tmp / "fx"
        generate_fixtures.generate(cls.fx, include_50mib=False)
        cls.out = cls.tmp / "out"
        cls.res = run_benchmark.run(cls.out, cls.fx, trials=TRIALS, warmup=WARMUP, app_trials=2, only=ONLY, verbose=False)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_three_selected_algorithms_are_benchmarked(self):
        rows = list(csv.DictReader(open(self.out / "raw_results.csv")))
        self.assertEqual(set(REQUIRED_ALGORITHMS), {r["algorithm"] for r in rows})

    def test_output_files_exist_and_are_complete(self):
        for f in ("raw_results.csv", "summary.csv", "io_results.csv", "app_download_results.csv",
                  "ciphertext_comparison.json", "environment.json"):
            self.assertTrue((self.out / f).stat().st_size > 0, f)
        raw = list(csv.DictReader(open(self.out / "raw_results.csv")))
        # files x algorithms x ops x trials
        self.assertEqual(len(raw), len(ONLY) * len(ALGORITHMS) * 2 * TRIALS)
        self.assertEqual(self.res["raw_rows"], len(raw))
        self.assertTrue(all(int(r["time_ns"]) > 0 for r in raw))
        summ = list(csv.DictReader(open(self.out / "summary.csv")))
        self.assertEqual(len(summ), len(ONLY) * len(ALGORITHMS) * 2)
        for col in ("mean_s", "median_s", "stdev_s", "mean_throughput_MiBps", "median_throughput_MiBps", "n"):
            self.assertIn(col, summ[0])
        self.assertTrue(all(int(r["n"]) == TRIALS for r in summ))
        io = list(csv.DictReader(open(self.out / "io_results.csv")))
        self.assertEqual(len(io), len(ONLY) * TRIALS)

    def test_environment_records_required_details(self):
        env = json.loads((self.out / "environment.json").read_text())
        for k in ("python", "cryptography", "os", "processor", "trials", "warmup", "files", "algorithms", "openssl", "timed_region"):
            self.assertIn(k, env)
        self.assertEqual(env["trials"], TRIALS)

    def test_summary_statistics_are_consistent(self):
        import statistics as st
        raw = list(csv.DictReader(open(self.out / "raw_results.csv"))); summ = list(csv.DictReader(open(self.out / "summary.csv")))
        s = next(r for r in summ if r["algorithm"] == "AES-GCM" and r["op"] == "encrypt" and r["file"] == "text_1MiB.txt")
        vals = [int(r["time_ns"]) / 1e9 for r in raw if r["algorithm"] == "AES-GCM" and r["op"] == "encrypt" and r["file"] == "text_1MiB.txt"]
        self.assertAlmostEqual(float(s["mean_s"]), st.fmean(vals), places=7)
        self.assertAlmostEqual(float(s["median_s"]), st.median(vals), places=7)
        self.assertAlmostEqual(float(s["stdev_s"]), st.stdev(vals), places=7)

    def test_graphs_are_generated(self):
        # reduced fixture set has no 10 MiB file, so fig2/fig3 are correctly skipped
        made = make_plots.make(self.out, self.tmp / "graphs")
        self.assertEqual(sorted(p.name for p in made),
                         ["fig1_throughput_vs_size.png", "fig4_data_types.png", "fig5_app_download.png"])
        for p in made: self.assertGreater(p.stat().st_size, 1000)

    @unittest.skipUnless((Path(__file__).resolve().parent.parent / "benchmark/results/summary.csv").exists(),
                         "full benchmark results not present")
    def test_graphs_from_full_results_produce_all_five_figures(self):
        res = Path(__file__).resolve().parent.parent / "benchmark/results"
        made = make_plots.make(res, self.tmp / "graphs_full")
        self.assertEqual(len(made), 5)

    def test_ciphertext_comparison_content(self):
        c = json.loads((self.out / "ciphertext_comparison.json").read_text())
        self.assertEqual(c["same_key_same_iv_twice_identical"], {m: True for m in ciphertext_comparison.MODES})
        self.assertTrue(all(not c["same_key_fresh_random_iv_twice"][m]["identical"] for m in ("AES-GCM", "DES-CBC")))
        self.assertTrue(c["same_key_fresh_random_iv_twice"]["RC4"]["identical"])
        self.assertFalse(c["bit_flip_in_ciphertext_block_2"]["AES-GCM"]["plaintext_returned"])


class Reproducibility(unittest.TestCase):
    def test_lab_comparison_is_deterministic_apart_from_fresh_iv_noise(self):
        pt = os.urandom(0) or (b"reproducible plaintext " * 200)[:4096]
        a, b = ciphertext_comparison.run(pt), ciphertext_comparison.run(pt)
        for k in ("same_key_iv_plaintext", "pairwise_bit_difference_fraction", "ciphertext_size_by_plaintext_length",
                  "repeated_block_plaintext_duplicate_ciphertext_blocks_of_8", "bit_flip_in_ciphertext_block_2"):
            self.assertEqual(a[k], b[k], k)

    def test_selected_algorithms_on_varied_sizes_with_fixed_lab_key(self):
        key = ciphertext_comparison.LAB_KEY
        for m in REQUIRED_ALGORITHMS:
            for n in (0, 1, 15, 16, 17, 1000, 65537):
                data = bytes((i * 31) % 256 for i in range(n))
                iv = ciphertext_comparison._iv(m)
                self.assertEqual(raw_decrypt(m, key[:__import__("vault_crypto").ALGORITHMS[m]["key_len"]], iv, raw_encrypt(m, key[:__import__("vault_crypto").ALGORITHMS[m]["key_len"]], iv, data)), data, (m, n))


if __name__ == "__main__":
    unittest.main()
