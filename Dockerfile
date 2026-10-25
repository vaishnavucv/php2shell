FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements-tested.txt /app/requirements-tested.txt
RUN python -m pip install --no-cache-dir -r requirements-tested.txt \
    && groupadd --gid 10001 scanner \
    && useradd --uid 10001 --gid scanner --no-create-home scanner \
    && mkdir /reports \
    && chown scanner:scanner /reports

COPY scanner.py php_version.py template_method.py http_diagnostics.py assetnote_adapter.py /app/
COPY vendor/ /app/vendor/
COPY THIRD_PARTY_NOTICES.md METHOD_REFERENCE.md /app/

USER 10001:10001

FROM base AS test
COPY test_*.py /app/
RUN python -m unittest -v

FROM base AS runtime
# Immutable source identifier: CI passes the exact commit, baked into every
# report via the SIGIL_SOURCE_COMMIT env var (defaults to "unknown" locally).
ARG SIGIL_SOURCE_COMMIT=unknown
ENV SIGIL_SOURCE_COMMIT=${SIGIL_SOURCE_COMMIT}
LABEL org.opencontainers.image.title="SIGiL PHP2Shell Scanner" \
      org.opencontainers.image.version="1.0.0-rc7" \
      org.opencontainers.image.revision="${SIGIL_SOURCE_COMMIT}" \
      org.opencontainers.image.description="PHP2Shell assessment chain with attributed ProjectDiscovery and Assetnote methods"

ENTRYPOINT ["python", "/app/scanner.py"]
CMD ["--help"]
