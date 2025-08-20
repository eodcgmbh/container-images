FROM ghcr.io/dask/dask-gateway-server:2025.4.0
ARG DASK_EXT_DIR=/home/dask/dask-server-extensions
RUN pip install --no-cache-dir pyjwt && \
    mkdir $DASK_EXT_DIR
COPY dask_jwt_authenticator.py $DASK_EXT_DIR/dask_jwt_authenticator.py
ENV PYTHONPATH="$DASK_EXT_DIR"

