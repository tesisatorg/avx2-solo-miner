# avx2-solo-miner

**English** | [Türkçe](README.tr.md)

A hobby, **education-oriented** solo Bitcoin miner: PHP (Stratum v1 client and worker management) + C (multi-engine SHA-256d scanner: AVX-512, SHA-NI, AVX2) + optional Overt AsicBoost (BIP 310 version rolling).

> **Honest expectations:** this software will not make you money. A laptop i7 reaches roughly 40-50 MH/s while the network is around 1 ZH/s. The chance of finding a block solo is practically zero (hundreds of millions of years). The goal is to see and learn how mining and its optimizations work (midstate, round elimination, SIMD, AsicBoost). Keep electricity cost and CPU heat in mind.

## Features
- Midstate precomputation, nonce entering at round 3, 61-round shortcut for the second hash, constant-folded message schedule
- Several engines, chosen automatically for your CPU at start-up (the miner benchmarks them and takes the fastest):
  - `avx512`: 16 lanes, native rotates and ternary logic
  - `avx512vl`: 8 lanes with the same AVX-512 instructions
  - `shani`: Intel SHA extensions (also found on AMD Zen), several streams interleaved
  - `avx2`: 8 lanes, works on any CPU since 2013 (Haswell, Zen)
  - `scalar`: slow fallback that runs anywhere
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

## Setup
1. You need PHP 8+ (CLI) and GCC (MSYS2/MinGW on Windows).
2. Build (no extra flags needed, the engines are selected at run time):
   ```
   gcc -O3 -o sha256d_scan.exe sha256d_scan.c      # Windows
   gcc -O3 -o sha256d_scan sha256d_scan.c          # Linux
   ```
3. Copy `config.example.php` to `config.php` and put your own BTC address in it.
4. Verify: `php miner.php --selftest`
5. Run: `php miner.php` (all cores) or `php miner.php 6` (6 workers). Stop with Ctrl+C or by deleting `run.flag`.

Run it from the command line, not from a browser. Without the C program it falls back to a very slow pure-PHP mode.

Useful C program commands: `sha256d_scan --info` (engines found), `--test` (checks every engine), `--tune` (benchmark and pick the best), `--bench 16 avx2` (benchmark one engine). To force an engine, set the environment variable `SHA256D_ENGINE=avx2`.

## Heat and power
At full load the CPU can get very hot. On Windows, setting "Maximum processor state" to 99% disables turbo (about 20% slower, about 15 °C cooler). Using fewer workers than cores is another option.

## Pool
Default is `solo.ckpool.org:3333`. Your address is sent as the user name; if a block is found the reward goes directly to it. The pool's initial difficulty is high, so the miner asks for a lower one with `mining.suggest_difficulty`.

## Layout
- `miner.php`: Stratum client, worker processes, self-tests
- `sha256d_scan.c`: all engines in one file (generated)
- `tools/gen_kernels.py` + `tools/skeleton.c`: generator for the AVX2 / AVX-512 kernels. Rebuild with `python3 tools/gen_kernels.py tools/skeleton.c > sha256d_scan.c`
- `tests/`: mock pool for end-to-end testing
- `CHANGELOG.md`

## Responsibility
Use it only on your own hardware and with your own address. Running it on someone else's device without consent is illegal.

## License
MIT (see LICENSE).
