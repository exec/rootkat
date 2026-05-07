# Build environment for rootkat. Parameterized by UBUNTU_VERSION so the
# host installs kernel headers matching the QEMU cloud image we'll
# eventually run the modules against. Pinned to amd64 so Apple Silicon
# hosts cross-build correctly.
ARG UBUNTU_VERSION=26.04
FROM --platform=linux/amd64 ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# Base toolchain + kernel-build prerequisites. linux-headers-generic
# pulls in the right ABI version for the target Ubuntu release.
# bpftool is a real package on Ubuntu 26.04 but a virtual one on
# 24.04 (provided by linux-tools-X-generic). linux-tools-generic
# is the meta-package that pulls the per-kernel tools — works on both.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        zlib1g-dev \
        linux-tools-generic \
        linux-headers-generic \
        pkg-config \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Kernel-Rust support: only some Ubuntu releases ship the
# linux-lib-rust-X-generic package. We resolve the kernel ABI from the
# headers package we just installed, then try to install the matching
# lib-rust package. If unavailable (e.g. Ubuntu 24.04 / 6.8), we
# silently continue — rust/Makefile detects the absence and no-ops, and
# tests/qemu/test_rust_module.sh skips itself cleanly.
RUN apt-get update \
 && KABI=$(ls /usr/src 2>/dev/null \
            | grep -oE '^linux-headers-[0-9][0-9.A-Za-z-]+-generic$' \
            | head -n1 \
            | sed -e 's/^linux-headers-//' -e 's/-generic$//') \
 && echo "[rootkat] resolved kernel ABI: ${KABI}" \
 && if apt-get install -y --no-install-recommends \
        "linux-lib-rust-${KABI}-generic" rustc bindgen rust-src; then \
        rm -rf "/usr/src/linux-headers-${KABI}-generic/rust" \
     && ln -s "/usr/src/linux-lib-rust-${KABI}-generic/rust" \
              "/usr/src/linux-headers-${KABI}-generic/rust" \
     && echo "[rootkat] kernel-Rust support: ENABLED" ; \
    else \
        echo "[rootkat] kernel-Rust support: not available for ABI ${KABI}" ; \
    fi \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
