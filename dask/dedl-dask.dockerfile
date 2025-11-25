FROM mambaorg/micromamba:2.4.0-debian13
COPY --chown=$MAMBA_USER:$MAMBA_USER ../envs/dedl-core.yaml /tmp/dedl-core.yaml
RUN micromamba install --yes -n base --use-uv -f /tmp/dedl-core.yaml && \
    micromamba clean --all --yes
