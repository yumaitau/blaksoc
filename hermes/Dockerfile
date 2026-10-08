# syntax=docker/dockerfile:1.7
# Hermes (in-cluster agent): the official Hermes Agent image plus the Warden controller and blakSOC
# tuning toolset. Build from the repository root:
#   docker buildx build --platform linux/amd64 -f hermes/Dockerfile -t blaksoc-hermes:dev .
#
# Base pinned by digest: Hermes Agent v0.20.5 (Debian 13, Python 3.13 at /opt/hermes/.venv, boto3 and
# httpx included, so the Bedrock provider needs no runtime install). Bump deliberately, then rerun
# hermes/tests and an offline tool-surface check (deploy/aws/README.md, "Hermes (in-cluster agent)").
ARG HERMES_IMAGE=nousresearch/hermes-agent@sha256:b7bfc6a1d491c818cac588759ac6230afd2324cf30ed3ee9d21a5b0eea028c9e

FROM ${HERMES_IMAGE} AS hermes
USER root
# Numeric ids so Kubernetes can verify runAsNonRoot (the chart's hermes.podSecurityContext pins them).
# /app/no-plugins is deliberately empty: no bundled or project plugins load beside the Warden tools.
RUN mkdir -p /app/no-plugins /hermes-home && chown 10000:10000 /hermes-home
COPY --chown=0:0 hermes/warden /app/warden
ENV PYTHONPATH=/app:/opt/hermes \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HERMES_HOME=/hermes-home \
    HOME=/hermes-home \
    HERMES_DISABLE_LAZY_INSTALLS=1 \
    HERMES_ENABLE_PROJECT_PLUGINS=false \
    HERMES_BUNDLED_PLUGINS=/app/no-plugins \
    TZ=Australia/Sydney
# The upstream image starts as root through an entrypoint dispatcher; this image runs one controller
# process as an unprivileged user and exits.
WORKDIR /opt/hermes
USER 10000:10000
ENTRYPOINT ["/opt/hermes/.venv/bin/python", "-m", "warden"]
