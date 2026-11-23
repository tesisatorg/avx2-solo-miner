# Changelog

## v2.2
- **GPU support (OpenCL):** new `gpu_scan.c`. One GPU worker runs next to the CPU workers (about 173 MH/s on a GTX 950M, measured by the user). No OpenCL headers or libraries are needed to build: `OpenCL.dll` is loaded at run time.
- Run modes: `php miner.php` (CPU + GPU), `php miner.php gpu` (GPU only), `php miner.php cpu` (CPU only)
- GPU hits are re-verified on the CPU before they are submitted; `gpu_scan --test` compares the GPU with a scalar reference
- Settings: `GPU=0`, `GPU_DEVICES=2,0`, `GPU_DUTY=70` (heat), `GPU_LWS=128` (work-group size)
- The GPU kernel is generated from `tools/gpu/kernel.cl` + `tools/gpu/host.c.in` (`tools/gpu/gen_gpu.py`); `tests/gpu_kernel_check.py` checks the kernel with pyopencl
- Stability (v2.1 work, first published here): `clean_jobs` handling, exponential reconnect back-off, accepted/rejected share counters, restart of crashed workers, block hits saved to `BLOK_BULUNDU.txt`
- The miner no longer ships a default wallet address: `config.php` is required

## v2.0
- New engines: `avx512` (16 lanes), `avx512vl` (8 lanes), `shani` (SHA extensions), plus a `scalar` fallback for CPUs without AVX2
- Automatic engine selection at start-up (`--tune`); override with `SHA256D_ENGINE`
- Build no longer needs `-mavx2 -march=haswell`: plain `gcc -O3` works and the right instructions are chosen at run time
- `--test` now checks every available engine against the scalar reference
- Kernel generator rewritten (`tools/gen_kernels.py`)

## v1.0
- PHP Stratum client + AVX2 C kernel + Overt AsicBoost
