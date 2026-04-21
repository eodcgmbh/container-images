# EODC GPU Notebook — TensorFlow flavour
# Base: NVIDIA CUDA 12.8 + cuDNN (devel, Ubuntu 22.04)
#
# Included stacks:
#   - RAPIDS ecosystem  (cuDF, cuML, cuGraph, cuSpatial, dask-cuda)
#   - TensorFlow        (tensorflow[and-cuda], GPU-ready)
#   - Dask-ML           (dask-ml + XGBoost GPU + scikit-learn)
#   - JupyterLab 4      (dask-labextension, jupyter-fs)
#   - JupyterHub        (jupyterhub-singleuser, required for JupyterHub spawner)

ARG CUDA_VERSION=12.8.0
ARG UBUNTU_VERSION=22.04
FROM nvidia/cuda:${CUDA_VERSION}-cudnn-devel-ubuntu${UBUNTU_VERSION}

LABEL maintainer="EODC GmbH <support@eodc.eu>"

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive
ENV MAMBA_ROOT_PREFIX=/opt/conda
ENV PATH="${MAMBA_ROOT_PREFIX}/bin:${PATH}"
ENV PIP_NO_CACHE_DIR=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LD_LIBRARY_PATH="${MAMBA_ROOT_PREFIX}/lib:${LD_LIBRARY_PATH:-}"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update --yes \
 && apt-get install --yes --no-install-recommends \
      wget curl git ca-certificates \
      build-essential \
      libglib2.0-0 libsm6 libxext6 libxrender-dev \
      s3fs s3cmd \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# ── jovyan user (UID 1000 — matches JupyterHub's default expectation) ─────────
ARG NB_USER=jovyan
ARG NB_UID=1000
RUN useradd -m -s /bin/bash -u ${NB_UID} ${NB_USER}

# ── micromamba ────────────────────────────────────────────────────────────────
RUN curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest \
    | tar -xvj -C /usr/local/bin --strip-components=1 bin/micromamba \
 && micromamba shell init --shell bash --root-prefix "${MAMBA_ROOT_PREFIX}" \
 && chown -R ${NB_USER}:${NB_USER} "${MAMBA_ROOT_PREFIX}"

# ── Conda environment (RAPIDS + Dask-ML + JupyterLab + JupyterHub) ───────────
COPY envs/eodc-gpu.yaml /tmp/eodc-gpu.yaml
RUN micromamba install --yes -n base -f /tmp/eodc-gpu.yaml \
 && micromamba clean --all --yes

# ── Compile source-only JupyterLab extensions (e.g. @plotly/dash-jupyterlab) ─
RUN jupyter lab build --minimize=False -y \
 && jupyter lab clean -y

# ── TensorFlow with GPU support ───────────────────────────────────────────────
RUN pip install --no-cache-dir "tensorflow[and-cuda]"

# ── JupyterLab server config ──────────────────────────────────────────────────
COPY jupyterlab/jupyter_server_config.json /etc/jupyter/jupyter_server_config.json

WORKDIR /home/${NB_USER}
USER ${NB_USER}

EXPOSE 8888

CMD ["jupyter", "lab", \
     "--ip=0.0.0.0", \
     "--port=8888", \
     "--no-browser", \
     "--ServerApp.token=''"]
