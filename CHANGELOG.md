# Changelog

## v2.0
- New engines: `avx512` (16 lanes), `avx512vl` (8 lanes), `shani` (SHA extensions), plus a `scalar` fallback for CPUs without AVX2
- Automatic engine selection at start-up (`--tune`); override with `SHA256D_ENGINE`
- Build no longer needs `-mavx2 -march=haswell`: plain `gcc -O3` works and the right instructions are chosen at run time
- `--test` now checks every available engine against the scalar reference
- Kernel generator rewritten (`tools/gen_kernels.py`)

## v1.0
- PHP Stratum client + AVX2 C kernel + Overt AsicBoost
