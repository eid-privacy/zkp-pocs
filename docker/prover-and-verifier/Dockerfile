FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="/home/appuser/.local/bin:/home/appuser/.nargo/bin:/home/appuser/.venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl bash xz-utils \
    python3 python3-venv python3-pip \
    git \
    autoconf automake build-essential libffi-dev libtool pkg-config python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 appuser
USER appuser
WORKDIR /app

ENV HOME=/home/appuser

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Rust setup
ENV CARGO_HOME=/home/appuser/.cargo \
    RUSTUP_HOME=/home/appuser/.rustup \
    PATH="/home/appuser/.cargo/bin:${PATH}"

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable \
 && rustup component add rustfmt clippy \
 && rustc --version \
 && cargo --version

# Install Noir via noirup
RUN set -euo pipefail; \
    mkdir -p "${HOME}/.nargo/bin"; \
    curl -fsSL https://raw.githubusercontent.com/noir-lang/noirup/main/noirup \
      -o "${HOME}/.nargo/bin/noirup"; \
    chmod +x "${HOME}/.nargo/bin/noirup"; \
    "${HOME}/.nargo/bin/noirup"; \
    "${HOME}/.nargo/bin/nargo" --version

ENV PATH="${HOME}/.nargo/bin:${PATH}"


# Python deps
RUN python3 -m venv /home/appuser/.venv && \
    /home/appuser/.venv/bin/pip install --upgrade pip

# Copy Requirements and install
COPY --chown=appuser:appuser noir/requirements.txt /app/noir/requirements.txt
RUN if [ -f /app/noir/requirements.txt ]; then \
      pip install -r /app/noir/requirements.txt ; \
    else \
      echo "No noir/requirements.txt found, skipping Python deps"; \
    fi

# Copy project files
COPY --chown=appuser:appuser docknetwork /app/docknetwork
COPY --chown=appuser:appuser noir        /app/noir


RUN mkdir -p /app/bin && \
    touch /app/bin/time && \
    chmod +rwx /app/bin/time

WORKDIR /app

CMD [ "bash", "-lc", "nargo --version && echo 'Container ready. Run your nargo commands…'" ]