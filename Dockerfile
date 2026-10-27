FROM python:3.12-slim

# opengrep ships as a standalone binary (not on PyPI). Pinned version + checksum per architecture.
ARG OPENGREP_VERSION=1.32.0
ARG TARGETARCH
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) asset=opengrep_manylinux_x86;     sum=7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75 ;; \
      arm64) asset=opengrep_manylinux_aarch64; sum=dc6229319c0d68948733053786a5614873947e5ec1d4669cc0e94ae9038cb99d ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/${asset}" /usr/local/bin/opengrep; \
    echo "${sum}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod +x /usr/local/bin/opengrep

WORKDIR /opt/os-sast
COPY pyproject.toml README.md ./
COPY src ./src
# docker build --build-arg EXTRAS=scanners,bedrock -t os-sast .   to include boto3 for Bedrock
ARG EXTRAS=scanners
RUN pip install --no-cache-dir ".[${EXTRAS}]"

WORKDIR /src
ENTRYPOINT ["os-sast"]
CMD ["--help"]
