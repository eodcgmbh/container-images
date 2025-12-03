FROM ghcr.io/dask/dask-gateway-server:2025.4.0

ARG PIP_CACHE_DIR=/tmp/pip-cache
RUN --mount=type=cache,target=${PIP_CACHE_DIR} \
    --mount=type=cache,from=build-stage,source=/tmp/wheels,target=/tmp/wheels \
    pip install \
        --find-links=/tmp/wheels/ \
        prometheus_client==0.23.1
