# Post-quantum TLS and ECH as a step shift for network security monitoring

Testbed, derived flow tables, per-flow predictions and evaluation code accompanying the manuscript *Crypto-agility breaks the baseline: post-quantum TLS and Encrypted Client Hello as a step shift for network security monitoring*. The manuscript itself is not included in this repository.

The study asks what happens to flow-based monitoring when TLS migrates. It trains detectors on pre-migration traffic and tests them after each migration:
- hybrid post-quantum key exchange (X25519MLKEM768);
- ML-DSA-65 server certificates;
- Encrypted Client Hello (ECH).

It then measures what eight repairs cost.

## Testbed

The testbed is a factorial grid of 24 cells:
- **Stack and transport:** Go/TCP, OpenSSL/TCP and Go/QUIC.
- **Key exchange:** classical or hybrid.
- **Certificate:** ECDSA P-256 or ML-DSA-65.
- **ECH:** off or on.

**Network.** Each cell runs in a Mininet network with one server (Go `net/http` and `quic-go`) and eight clients. Each client sits on a 50 Mbit/s link with 20 ms one-way delay. Capture is at the server's interface.

**Workload.** Nine traffic profiles, each repeated 10 times, 20 s per run:
- six benign profiles: web page, API polling, download, upload, video and many short connections;
- three malicious behaviours: beaconing, credential guessing and a TLS handshake scan.

Seeds depend only on (profile, repetition), so every cell replays the same workload. Every behaviour targets only the lab's own server inside the emulated network.

Cell names follow `<stack>-<transport>-<kx>-<cert>-ech<on|off>`, e.g. `openssl-tcp-hybrid-mldsa-echon`.

## Layout

| Path | Contents |
|---|---|
| `lab/setup_tls.sh` | Builds Go 1.27.1, OpenSSL 4.0.3 and curl 8.16.0 under `$LAB` (default `/opt/p1920b`) |
| `lab/test_tls.sh` | Generates the test PKI (ECDSA and ML-DSA CAs and server certificates) and the ECH key, and checks every OpenSSL handshake combination |
| `lab/gotls/tlslab.go` (+ `go.mod`, `go.sum`) | Go server (HTTP/1.1 over TCP, HTTP/3 over QUIC) and Go client with the nine profiles |
| `lab/test_go.sh` | Converts the keys for Go and checks every Go and OpenSSL client against the Go server |
| `lab/b_osslclient.py` | OpenSSL-stack client: the same nine profiles driven through `openssl s_client` |
| `lab/b_twin.py`, `lab/run_grid.sh` | Mininet orchestration of one cell or the whole grid (resumable) → `$LAB/caps/<cell>/capture.pcap` + `runs.json` |
| `lab/b_extract.py` | Per-cell flow extraction. NFStream features and nDPI JA4, plus an own dpkt pass for JA3, ClientHello metadata, the handshake boundary, whole-flow and post-handshake statistics, and the first 6 × 100 payload bytes |
| `lab/b_realworld.sh`, `lab/b_realworld_parse.py` | External check: ClientHello and handshake sizes against eight public servers, classical vs hybrid group list |
| `data/b_flows/<cell>.csv.gz` | One row per flow (44,496 flows in 24 cells) with labels, NFStream and own features; the analysis keeps the 44,386 TCP and UDP flows and drops ICMP |
| `data/b_flows/<cell>_bytes.npy` | First 6 payload packets × 100 bytes per flow (uint8), input of the byte-level CNN |
| `data/b_runs/<cell>.json` | Run schedule of every cell: client, profile, repetition, seed, label, start and end times |
| `data/b_flows_pad/<cell>.csv.gz`, `data/b_runs_pad/<cell>.json` | Padded and benign-sized attacks, recaptured in all 24 cells: `beacon_rand` (random request padding 0–1,024 B, response 64–16,384 B), `brute_rand` (form padded with 0–4,096 B), `beacon_mimic` (beacon with the sizes of the benign `many_short` profile) |
| `data/b_realworld.csv` | Public-server handshake measurements |
| `src/b_detect.py` | Detectors and repairs on one fold → `results/b_eval.json` (fold 0) or `results/b_eval_f<k>.json`; fold 0 also writes `results/b_pred.csv.gz` |
| `src/b_stats.py` | Paired run-level bootstrap and factor models on the per-flow predictions → `results/b_stats.json` |
| `src/b_mixed.py`, `src/b_mixed_report.py` | Uneven migration (benign clients first, attackers first, staggered retraining) → `results/b_mixed*.json`, `results/b_mixed_summary.json` |
| `src/b_robust.py`, `src/b_robust_report.py` | Robustness analyses → `results/b_robust.json`: precision at realistic base rates, the 5 % operating point, per-cell bootstrap intervals, five model seeds per fold, stability of the main effects, and label-free shift alarms (KS / PSI) |
| `src/b_padding.py`, `src/b_padding_report.py` | Is the post-handshake repair (R1) robust to padded or benign-sized attacks? Matched (trained on the padded attacks) and evasion (trained on the original attacks) regimes → `results/b_padding*.json` |
| `src/b_report.py` | Number macros, tables and figures → `outputs/`; also writes `results/b_handshake.csv` |
| `results/` | All evaluation results used in the manuscript (three folds; `b_eval_f<k>_s<r>.json` are the reruns with model seeds 1–4) |
| `figures/` | PNG renderings of the figures |

**Detectors.** All are trained on the pre-migration baseline (classical key exchange, ECDSA, ECH off), with thresholds set at 1 % and 5 % FPR on its benign calibration flows:
- supervised: LightGBM, random forest and MLP on NFStream features;
- benign-only: Isolation Forest;
- a byte-level CNN;
- JA3/JA4 fingerprint coverage.

**Repairs:**
- **R0:** threshold recalibrated on clean post-migration benign flows.
- **R1:** post-handshake statistics plus a handshake-completed flag. **R1⁻** is R1 without the flag; **R1b** drops the first-packet features.
- **R2:** few-shot retraining (1/5/10 %). **R2b** uses a class-balanced sample; **R2r** adds R0's threshold.
- **R3:** full retraining.
- **Control:** the cell's own whole-flow statistics.

**Folds.** Fold 0 (main) trains on repetitions 0–3, calibrates on 4–5 and tests on 6–9. Folds 1 and 2 rotate the repetitions.

## Reproduce

```bash
pip install -r requirements.txt
```

**From the committed flow tables (no testbed needed).** These steps reproduce every number, table and figure:

```bash
python src/b_detect.py 0         # main fold   -> results/b_eval.json, results/b_pred.csv.gz
python src/b_detect.py 1         # fold 1      -> results/b_eval_f1.json
python src/b_detect.py 2         # fold 2      -> results/b_eval_f2.json
python src/b_stats.py            # -> results/b_stats.json
python src/b_mixed.py 0; python src/b_mixed.py 1; python src/b_mixed.py 2
python src/b_mixed_report.py     # -> results/b_mixed_summary.json
for s in 1 2 3 4; do for f in 0 1 2; do python src/b_detect.py $f $s; done; done   # seed reruns (about 30 min)
python src/b_robust.py           # -> results/b_robust.json (needs the seed reruns; about 5 min)
python src/b_padding.py 0; python src/b_padding.py 1; python src/b_padding.py 2   # -> results/b_padding*.json
python src/b_report.py           # -> outputs/ (number macros, tables, figures)
```

`b_report.py` alone regenerates the tables and figures from the committed `results/`. The byte-level CNN uses a GPU when PyTorch finds one and runs on the CPU otherwise.

**Full rebuild of the testbed (Linux or WSL2, as root, with Mininet and Open vSwitch).**

```bash
export LAB=/opt/p1920b                              # no spaces in this path
bash lab/setup_tls.sh                               # Go, OpenSSL 4.0.3, curl
bash lab/test_tls.sh                                # test PKI + ECH key in $LAB/pki
mkdir -p $LAB/gotls && cp lab/gotls/* $LAB/gotls/ && (cd $LAB/gotls && $LAB/go/bin/go build -o tlslab .)
bash lab/test_go.sh                                 # key conversion + handshake checks
bash lab/run_grid.sh                                # 24 cells -> $LAB/caps (about 3.2 GB)
LAB=$LAB CAP=$LAB/caps_pad REPS=10 DUR=20 ONLY=beacon_rand,brute_rand,beacon_mimic python3 lab/b_twin.py all   # padded attacks (about 45 min)
CAP=$LAB/caps_pad OUT=data/b_flows_pad python3 lab/b_extract.py
python3 lab/b_extract.py                            # -> data/b_flows/
bash lab/b_realworld.sh && python3 lab/b_realworld_parse.py   # -> data/b_realworld.csv
```

Python packages on the lab side: `mininet` 3.0, `nfstream` 6.6.0, `dpkt` 1.9.8 (Ubuntu 22.04).

## Notes

- **What is not included:**
  - The raw packet captures (about 3.2 GB) are too large for GitHub. They can be regenerated with the steps above; the derived flow tables in `data/b_flows/` are what every analysis reads.
  - The public-server captures are left out because they contain the capturing machine's address. Their measurements are in `data/b_realworld.csv`.
  - Private keys are never committed. `lab/test_tls.sh` creates a fresh test PKI and ECH key for every rebuild.
- **Regenerated captures differ in detail.** A rebuilt testbed produces new keys and new timing, so its flows differ in detail from the committed ones. Expect the same effects, not identical numbers.
- **Determinism.** From the committed `results/`, `b_report.py`, `b_mixed_report.py` and `b_stats.py` reproduce every number in the manuscript exactly (bootstrap intervals can differ in the last floating-point digits). Retraining from the flow tables with `b_detect.py` and `b_mixed.py` reproduces the LightGBM, random-forest, MLP, Isolation Forest, fingerprint and uneven-migration results. The one exception is the byte-level CNN, whose GPU training is not bit-for-bit deterministic; in our rerun it moved by up to 1 percentage point in two QUIC cells. Main fold: about 2.5 min for `b_detect.py` and 45 s for `b_mixed.py` on a GTX 1060.
- **Lab addresses.** Clients are 10.0.0.11–18 and the server is 10.0.0.1 (`www.example.test`, ECH public name `public.example.test`). The MAC addresses in the flow tables are Mininet's random ones.

## Licence

- **Code:** MIT (see `LICENSE`).
- **Data:** the flow tables, run schedules and results were generated in the authors' own testbed and are released under CC BY 4.0.

## Citation

See `CITATION.cff`.
