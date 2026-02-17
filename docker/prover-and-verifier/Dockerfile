FROM rust:1-bullseye AS build

# System deps needed to compile Noir and its dependencies
RUN apt-get update && apt-get install -y \
    build-essential cmake clang pkg-config libssl-dev git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/noir-lang/noir.git .
# Checkout the specific version of Noir we want to use (sadly this is not available with noirup for arm64 hence why we have to clone the repo and build from source)
RUN git checkout v1.0.0-beta.13
RUN git submodule update --init --recursive

RUN cargo build --release

FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH="/home/appuser/.local/bin:/home/appuser/.nargo/bin:/home/appuser/.venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl bash xz-utils \
    jq \
    python3 python3-venv python3-pip \
    git \
    autoconf automake build-essential libffi-dev libtool pkg-config python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/nargo /usr/local/bin/nargo

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


# Install add noir to path
ENV PATH="/usr/local/bin:${PATH}"

# Install Barretenberg via bbup
RUN curl -fsSL https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install \
  | bash -s -- -y

RUN "$HOME/.bb/bbup" --version 1.2.1

# Add barretenberg to PATH
ENV PATH="$HOME/.bb:${PATH}"

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

COPY --chown=appuser:appuser docker/prover-and-verifier/default-cmd.sh /usr/local/bin/default-cmd.sh
RUN chmod +x /usr/local/bin/default-cmd.sh

COPY --chown=appuser:appuser docker/prover-and-verifier/prover-cmd.sh /usr/local/bin/prover-cmd.sh
RUN chmod +x /usr/local/bin/prover-cmd.sh

COPY --chown=appuser:appuser docker/prover-and-verifier/verifier-cmd.sh /usr/local/bin/verifier-cmd.sh
RUN chmod +x /usr/local/bin/verifier-cmd.sh

WORKDIR /app

CMD ["/usr/local/bin/default-cmd.sh"]