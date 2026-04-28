# EODC GPU Notebook — Full EO/AI (PyTorch + TensorFlow + Anemoi)
# Base: NVIDIA CUDA 12.8 + cuDNN (devel, Ubuntu 22.04)
#
# Included stacks:
#   - RAPIDS ecosystem      (cuDF, cuML, cuGraph, cuSpatial, dask-cuda)
#   - PyTorch + Lightning   (CUDA 12.8 wheels, torchgeo, timm, segmentation-models)
#   - TensorFlow            (tensorflow[and-cuda], GPU-ready)
#   - Anemoi                (ECMWF AI weather forecasting framework)
#   - HuggingFace           (transformers, datasets, accelerate — via conda)
#   - NWP / EO tools        (eccodes, cfgrib, earthkit-data, cartopy)
#   - MLOps                 (mlflow, onnxruntime-gpu, tensorboard)
#   - Dask-ML               (dask-ml + XGBoost GPU + scikit-learn + LightGBM)
#   - JupyterLab 4          (dask-labextension, jupyter-fs, tensorboard extension)
#   - JupyterHub            (jupyterhub-singleuser, required for JupyterHub spawner)

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
ENV LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:${MAMBA_ROOT_PREFIX}/lib"

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update --yes \
 && apt-get install --yes --no-install-recommends \
      wget curl git ca-certificates \
      build-essential \
      libglib2.0-0 libsm6 libxext6 libxrender-dev \
      libeccodes-dev \
      s3fs s3cmd \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# ── jovyan user ───────────────────────────────────────────────────────────────
ARG NB_USER=jovyan
ARG NB_UID=1000
RUN useradd -m -s /bin/bash -u ${NB_UID} ${NB_USER}

# ── micromamba ────────────────────────────────────────────────────────────────
RUN curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest \
    | tar -xvj -C /usr/local/bin --strip-components=1 bin/micromamba \
 && micromamba shell init --shell bash --root-prefix "${MAMBA_ROOT_PREFIX}" \
 && chown -R ${NB_USER}:${NB_USER} "${MAMBA_ROOT_PREFIX}"

# ── Conda environment ─────────────────────────────────────────────────────────
# Installs: RAPIDS, HuggingFace (via conda-forge, avoids pyarrow build conflicts),
# classical ML, geo stack, NWP tools, JupyterLab.
# PyTorch, TF, Lightning and Anemoi are installed via pip below to keep the
# conda solve simple and allow the pytorch special wheel index.
COPY envs/eodc-gpu-full.yaml /tmp/eodc-gpu-full.yaml
RUN micromamba install --yes -n base -f /tmp/eodc-gpu-full.yaml \
 && micromamba clean --all --yes

# ── PyTorch with CUDA 12.8 ────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
    torch torchvision torchaudio \
    --index-url https://download.pytorch.org/whl/cu128

# ── PyTorch ecosystem ─────────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
    lightning \
    timm \
    einops \
    segmentation-models-pytorch \
    torchgeo \
    kornia \
    onnxruntime-gpu

# ── TensorFlow with GPU support ───────────────────────────────────────────────
RUN pip install --no-cache-dir "tensorflow[and-cuda]"

# ── Anemoi (ECMWF AI weather forecasting framework) ───────────────────────────
RUN pip install --no-cache-dir \
    anemoi-utils \
    anemoi-datasets \
    anemoi-graphs \
    anemoi-models \
    anemoi-training \
    anemoi-inference

# ── EODC / ECMWF packages ─────────────────────────────────────────────────────
# Installed last — these pull pyarrow transitively; by this point conda has
# already installed pyarrow (via rapids), so pip finds it satisfied and skips
# building from source.
RUN pip install --no-cache-dir \
    rich \
    earthkit-data

# ── Compile source-only JupyterLab extensions ────────────────────────────────
RUN jupyter lab build --minimize=False -y \
 && jupyter lab clean -y

# ── JupyterLab server config ──────────────────────────────────────────────────
COPY jupyterlab/jupyter_server_config.json /etc/jupyter/jupyter_server_config.json

COPY jupyterlab/start.sh /usr/local/bin/start.sh

WORKDIR /home/${NB_USER}
USER ${NB_USER}

EXPOSE 8888

ENTRYPOINT ["/usr/local/bin/start.sh"]
CMD ["jupyter", "lab", \
     "--ip=0.0.0.0", \
     "--port=8888", \
     "--no-browser", \
     "--ServerApp.token=''"]
