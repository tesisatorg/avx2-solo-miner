# avx2-solo-miner

**English** | [Türkçe](README.tr.md)

A hobby, **education-oriented** solo Bitcoin miner: PHP (Stratum v1 client and worker management) + C (multi-engine SHA-256d scanner: AVX-512, SHA-NI, AVX2) + an optional OpenCL GPU scanner + optional Overt AsicBoost (BIP 310 version rolling).

> **Honest expectations:** this software will not make you money. A laptop i7 reaches roughly 40-50 MH/s (about 200 MH/s together with an old laptop GPU) while the network is around 1 ZH/s. The chance of finding a block solo is practically zero (hundreds of millions of years). The goal is to see and learn how mining and its optimizations work (midstate, round elimination, SIMD, AsicBoost). Keep electricity cost and CPU heat in mind.

## Features
- Midstate precomputation, nonce entering at round 3, 61-round shortcut for the second hash, constant-folded message schedule
- Several engines, chosen automatically for your CPU at start-up (the miner benchmarks them and takes the fastest):
  - `avx512`: 16 lanes, native rotates and ternary logic
  - `avx512vl`: 8 lanes with the same AVX-512 instructions
  - `shani`: Intel SHA extensions (also found on AMD Zen), several streams interleaved
  - `avx2`: 8 lanes, works on any CPU since 2013 (Haswell, Zen)
  - `scalar`: slow fallback that runs anywhere
- Optional OpenCL GPU scanner (`gpu_scan.c`): runs as one extra worker, works with NVIDIA, AMD and Intel GPUs that have an OpenCL driver
- Every hit is re-verified with scalar code before it is submitted
- Overt AsicBoost: the second-chunk message schedule is shared across many block versions
- `--selftest`: genesis block, merkle folding, nbits target, and every engine checked against a scalar reference

## Measured speed (single thread, M=16 versions)
Measured on one machine only: an Intel Xeon VM with AVX-512 and SHA-NI. Your CPU will differ; the miner picks the fastest engine itself.

| Engine | MH/s per thread |
| --- | --- |
| avx512 | ~45 |
| avx512vl | ~29 |
| shani | ~15.5 |
| avx2 | ~15 |
| scalar | ~1.5 |

On an AVX2-only laptop (i7-6700HQ, no AVX-512, no SHA-NI) the `avx2` engine gives about 40-52 MH/s on all cores. The other engines need newer CPUs and were not measured there.

### Measured on the same laptop (Lenovo IdeaPad 700-15ISK)
| Setup | Speed |
| --- | --- |
| CPU only (`php miner.php cpu`) | ~40 MH/s (about 50 with the 99% power cap removed) |
| GPU only: GTX 950M (`php miner.php gpu`) | ~173 MH/s |
| CPU + GPU (`php miner.php`) | ~205 MH/s |
| Intel HD 530 (integrated), `gpu_scan --bench` | ~30 MH/s (not used by default: it shares heat and power with the CPU) |

These are single-machine numbers. A GPU worker has no AsicBoost (one block version only), the GPU kernel is a plain one-nonce-per-work-item design and was not hand-tuned.

## Setup
1. You need PHP 8+ (CLI) and GCC (MSYS2/MinGW on Windows).
2. Build (no extra flags needed, the engines are selected at run time):
   ```
   gcc -O3 -o sha256d_scan.exe sha256d_scan.c      # Windows
   gcc -O3 -o sha256d_scan sha256d_scan.c          # Linux
   ```
3. Copy `config.example.php` to `config.php` and put your own BTC address in it.
4. Verify: `php miner.php --selftest`
5. Run: `php miner.php` (all cores + GPU if available), `php miner.php 6` (6 CPU workers), `php miner.php cpu` (CPU only) or `php miner.php gpu` (GPU only). Stop with Ctrl+C or by deleting `run.flag`.

### GPU (optional)
```
gcc -O3 -static -o gpu_scan.exe gpu_scan.c      # Windows (no OpenCL SDK needed)
gcc -O3 -o gpu_scan gpu_scan.c -ldl             # Linux
gpu_scan --info                                 # list OpenCL devices
gpu_scan --test                                 # GPU vs CPU reference, must print TEST OK
gpu_scan --bench                                # about 5 seconds, prints MH/s
```
If `gpu_scan` is next to `miner.php` and its test passes, a GPU worker starts automatically. Settings (environment variables): `GPU=0` disables it, `GPU_DEVICES=2,0` picks devices by the numbers shown by `--info`, `GPU_DUTY=70` limits the GPU to 70% of the time (less heat), `GPU_LWS=128` sets the work-group size. By default the first discrete NVIDIA/AMD GPU is used. Keep an eye on temperatures: CPU and GPU share one cooling system in most laptops.

Run it from the command line, not from a browser. Without the C program it falls back to a very slow pure-PHP mode.

Useful C program commands: `sha256d_scan --info` (engines found), `--test` (checks every engine), `--tune` (benchmark and pick the best), `--bench 16 avx2` (benchmark one engine). To force an engine, set the environment variable `SHA256D_ENGINE=avx2`.

## Heat and power
At full load the CPU can get very hot. On Windows, setting "Maximum processor state" to 99% disables turbo (about 20% slower, about 15 °C cooler). Using fewer workers than cores is another option.

## Pool
Default is `solo.ckpool.org:3333`. Your address is sent as the user name; if a block is found the reward goes directly to it. The pool's share difficulty is high (10000 on solo.ckpool.org): the miner asks for a lower one with `mining.suggest_difficulty`, but the pool decides. At about 200 MH/s one share takes days on average, so "accepted: 0" is normal; solo mining pays only when a whole block is found.

## Layout
- `miner.php`: Stratum client, worker processes, self-tests
- `sha256d_scan.c`: all CPU engines in one file (generated)
- `gpu_scan.c`: OpenCL GPU scanner (generated from `tools/gpu/`). `python3 tools/gpu/gen_gpu.py > gpu_scan.c`
- `tools/gen_kernels.py` + `tools/skeleton.c`: generator for the AVX2 / AVX-512 kernels. Rebuild with `python3 tools/gen_kernels.py tools/skeleton.c > sha256d_scan.c`
- `tests/`: mock pools for end-to-end testing, `gpu_kernel_check.py` for the GPU kernel
- `CHANGELOG.md`

## Responsibility
Use it only on your own hardware and with your own address. Running it on someone else's device without consent is illegal.

## License
MIT (see LICENSE).
