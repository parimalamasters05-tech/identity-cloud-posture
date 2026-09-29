# syntax=docker/dockerfile:1

# WeasyPrint needs Pango, cairo and HarfBuzz, which is the main reason this
# image exists: it makes PDF generation reproducible instead of a per-laptop
# yak-shave. Running the collector in a container also gives the engagement a
# clean, disposable environment per client, which is worth having when the
# thing you are handling is a map of someone's identity configuration.
#
# Two stages, so the runtime image carries no compiler and no build toolchain.

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# pyproject declares `readme = "README.md"`, so the build fails without it.
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install .


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

# WeasyPrint runtime libraries only. libharfbuzz-subset0 is not optional in
# practice: without it WeasyPrint falls back to fontTools and warns on every
# font, on every page, of every report.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz-subset0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        libffi8 \
        fonts-dejavu-core \
        fonts-liberation2 \
    && rm -rf /var/lib/apt/lists/* \
    && fc-cache -f

# Never run the collector as root. A tool whose entire pitch is least privilege
# should hold itself to it.
#
# UID 10001 is fixed and documented because bind-mounting a host directory for
# snapshots requires the host side to be writable by this UID. See the Docker
# section of the README.
RUN groupadd --gid 10001 icp \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin icp

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    XDG_CACHE_HOME=/tmp/.cache \
    ICP_SNAPSHOT_DIR=/work/snapshots \
    ICP_OUTPUT_DIR=/work/output \
    ICP_CONFIG_DIR=/work/config \
    ICP_FIXTURE_DIR=/work/fixtures

WORKDIR /work

# Config is the product: the scope taxonomy and the remediation library. Baked
# in so the image is self-contained, and overridable with a read-only bind mount
# while you are iterating on wording.
COPY --chown=icp:icp config ./config
COPY --chown=icp:icp fixtures ./fixtures

# Mount points for client data. Deliberately empty in the image itself -- a
# snapshot must never end up in a layer that could be pushed to a registry.
RUN mkdir -p /work/snapshots /work/output \
    && chown -R icp:icp /work \
    && chmod 700 /work/snapshots /work/output

USER 10001:10001

# Build-time smoke test. Fails the build if the scope allowlist, the rule
# registry, or the remediation library is broken, without contacting anything.
#
# This replaces a HEALTHCHECK: healthchecks only apply to long-running
# containers, and this image runs a command and exits.
RUN icp verify-scopes > /dev/null \
    && icp list-rules > /dev/null \
    && python -c "import weasyprint; weasyprint.HTML(string='<p>ok</p>').write_pdf('/tmp/smoke.pdf')" \
    && rm -f /tmp/smoke.pdf

LABEL org.opencontainers.image.title="Identity & Cloud Posture Health Check" \
      org.opencontainers.image.description="Read-only Google Workspace identity posture assessment" \
      org.opencontainers.image.licenses="Proprietary"

ENTRYPOINT ["icp"]
CMD ["--help"]
