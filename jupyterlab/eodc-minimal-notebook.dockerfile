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

RUN pip install --no-cache-dir --upgrade \
  # fix to make git labextension working for authentication
  pexpect==4.9.0 \
  jupyterlab_widgets \
  dask-labextension \
  #jupyterlab-s3-browser \
  nbgitpuller \
  psycopg2-binary \
  odc-stac==0.3.9 \
  zarr \
  eodc

RUN jupyter lab build --minimize=False -y

RUN pip install --no-cache-dir --upgrade jupyter-fs
COPY ./jupyter_server_config.json /etc/jupyter/jupyter_server_config.json

USER ${NB_UID}