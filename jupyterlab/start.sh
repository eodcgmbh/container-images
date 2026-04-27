#!/bin/bash
# Entrypoint for EODC GPU notebook images.
#
# numba-cuda loads libcuda.so via ctypes and doesn't search the paths where the
# NVIDIA Container Runtime injects the driver at runtime. This script finds it
# dynamically and exports NUMBA_CUDA_DRIVER before JupyterLab starts, so that
# cuDF/cuML work alongside PyTorch and TensorFlow without manual workarounds.

# Root order matters — do not `sort` or /usr/lib wins over /usr/local/...
LIBCUDA=$(find \
    /usr/local/nvidia/lib64 \
    /usr/local/cuda-12.8/compat \
    /usr/local/cuda/lib64 \
    /usr/lib \
    /usr/lib/x86_64-linux-gnu \
    -name "libcuda.so*" 2>/dev/null \
    | head -1)

if [ -n "$LIBCUDA" ]; then
    export NUMBA_CUDA_DRIVER="$LIBCUDA"
    echo "[start.sh] NUMBA_CUDA_DRIVER=${NUMBA_CUDA_DRIVER}"
else
    echo "[start.sh] Warning: libcuda.so not found — numba-cuda/cuDF may not work"
fi

exec "$@"
