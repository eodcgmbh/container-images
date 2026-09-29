# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
ARG REGISTRY=quay.io
ARG OWNER=jupyter
ARG TAG=python-3.11.10
ARG BASE_IMAGE=$REGISTRY/$OWNER/minimal-notebook:$TAG
FROM $BASE_IMAGE

LABEL maintainer="EODC Gmbh <support@eodc.eu>"

# Fix: https://github.com/hadolint/hadolint/wiki/DL4006
# Fix: https://github.com/koalaman/shellcheck/wiki/SC3014
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

USER root

RUN apt-get update --yes && \
  apt-get install --yes --no-install-recommends \
  # for cython: https://cython.readthedocs.io/en/latest/src/quickstart/install.html
  build-essential \
  # for latex labels
  cm-super \
  dvipng \
  # for matplotlib anim
  ffmpeg \
  # s3 support
  s3fs \
  s3cmd && \
  apt-get clean && rm -rf /var/lib/apt/lists/*

ARG CODE_SERVER_VERSION=4.139.1
RUN curl -fsSL -o /tmp/code-server.deb \
  "https://github.com/coder/code-server/releases/download/v${CODE_SERVER_VERSION}/code-server_${CODE_SERVER_VERSION}_amd64.deb" && \
  dpkg -i /tmp/code-server.deb && \
  rm /tmp/code-server.deb

RUN pip install --no-cache-dir --upgrade \
  # fix to make git labextension working for authentication
  pexpect==4.9.0 \
  jupyterlab_widgets \
  dask-labextension \
  #jupyterlab-s3-browser \
  nbgitpuller \
  xarray>=2024.10.0 \
  jupyterhub==5.4.1\
  psycopg2-binary \
  odc-stac==0.3.9 \
  zarr>=3.0.0 \
  eodc-connect \
  jupyter-vscode-proxy==0.7

RUN jupyter lab build --minimize=False -y

RUN pip install --no-cache-dir --upgrade jupyter-fs
