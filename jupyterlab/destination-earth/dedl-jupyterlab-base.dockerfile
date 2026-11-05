# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
ARG REGISTRY=quay.io
ARG OWNER=jupyter
ARG TAG=python-3.13.14
ARG BASE_IMAGE=$REGISTRY/$OWNER/minimal-notebook:$TAG

FROM $BASE_IMAGE AS base

LABEL maintainer="EODC Gmbh <support@eodc.eu>"

ENV PYTHONDONTWRITEBYTECODE=1
ENV CONDA_OVERRIDE_CUDA=""

USER root
RUN apt-get update && \
    apt-get install -y \
    s3fs \
    s3cmd  \
    gcc && \
    apt-get clean -y
# Dirtyfrag mitigation
RUN sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"
USER ${NB_UID}

# install lab extensions and dependencies of those
RUN pip install --no-cache-dir --upgrade \
    eodag-labextension==5.3.1 \
    eodag==4.9.1 \
    jupyterlab-git \
    nbgitpuller \
    dask-labextension \
    jupyterlab_widgets \
    jupyter_contrib_nbextensions
RUN mamba install -y -c conda-forge s5cmd && \
    mamba clean --all -f -y

# disable Alt-based shortcuts that swallow AltGr characters ({ [ ] } | \ @) on European keyboard layouts
COPY --chown=${NB_UID}:${NB_GID} \
    jupyterlab/destination-earth/jupyterlab_files/overrides.json \
    "${CONDA_DIR}/share/jupyter/lab/settings/overrides.json"

# add kernels to base image
from base as build_kernel
ARG env_name="python_dedl"
ARG display_name="Python DEDL"

USER root
COPY --chown=${NB_UID}:${NB_GID} envs/dedl-core.yaml ./core-conda.yaml
COPY --chown=${NB_UID}:${NB_GID} \
    jupyterlab/destination-earth/jupyterlab_files/.condarc  \
    "${CONDA_DIR}/.condarc.user"

RUN mamba clean -a && \
    mamba env create -p "${CONDA_DIR}/envs/${env_name}" -f ./core-conda.yaml && \
    mamba clean --all -f -y && \
    "${CONDA_DIR}/envs/${env_name}/bin/python" -m ipykernel install --name="${env_name}" --display-name="${display_name}" && \
    fix-permissions "${CONDA_DIR}" && \
    fix-permissions "/home/${NB_USER}" && \
    rm ./core-conda.yaml

RUN rm -rf /opt/conda/share/jupyter/kernels/python3  && \
    cp /home/jovyan/.bashrc /etc/bash.bashrc && \
    sed -i -e $'$a\\\n#active DEDL env \\nconda activate python_dedl' /etc/bash.bashrc

# configuration needed for eodag and eodag lab extension
COPY --chown=root:users --chmod=664 jupyterlab/destination-earth/jupyterlab_files/collections.yml /opt/conda/envs/python_dedl/lib/python3.1/site-packages/eodag/resources/collections.yml

# Dirtyfrag mitigation
RUN sh -c "printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf; rmmod esp4 esp6 rxrpc 2>/dev/null; echo 3 > /proc/sys/vm/drop_caches; true"

USER ${NB_UID}

# configuration needed for eodag and eodag lab extension
ENV EODAG_LABEXTENSION__MAP__TILE_URL="https://gisco-services.ec.europa.eu/maps/wmts/OSMPositronComposite/EPSG3857/{z}/{x}/{y}.png" \
    EODAG_LABEXTENSION__MAP__TILE_ATTRIBUTION="&copy (C) EuroGeographics for the administrative boundaries." \
    EODAG_LABEXTENSION__DEBUG=false \
    #EODAG_LABEXTENSION__MAP__ZOOM_OFFSET=-1 \
    EODAG_PRODUCT_TYPES_CFG_FILE="/opt/conda/envs/python_dedl/lib/python3.1/site-packages/eodag/resources/collections.yml"

