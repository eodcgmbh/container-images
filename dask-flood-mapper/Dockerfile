ARG REGISTRY=quay.io
ARG OWNER=jupyter
ARG BASE_IMAGE=$REGISTRY/$OWNER/base-notebook:python-3.11.6
FROM $BASE_IMAGE

USER root

RUN apt-get update --yes && \
    apt-get install --yes --no-install-recommends \
    curl git nano-tiny vim-tiny less && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

USER ${NB_UID}

COPY --chown=${NB_UID}:${NB_GID} environment.yaml /tmp/environment.yaml
RUN mamba env update -n base -f /tmp/environment.yaml && \
    fix-permissions "${CONDA_DIR}" && \
    fix-permissions "/home/${NB_USER}"

RUN curl -L https://raw.githubusercontent.com/interTwin-eu/dask-flood-mapper/refs/heads/workshop-f/notebooks/workshop.ipynb \
    -o /home/jovyan/workshop.ipynb

CMD ["jupyter", "lab", "/home/jovyan/workshop.ipynb", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]
