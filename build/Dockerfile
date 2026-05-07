# Build environment for rootkat. Parameterized by UBUNTU_VERSION so the
# host installs kernel headers matching the QEMU cloud image we'll
# eventually run the modules against. Pinned to amd64 so Apple Silicon
# hosts cross-build correctly.
ARG UBUNTU_VERSION=26.04
FROM --platform=linux/amd64 ubuntu:${UBUNTU_VERSION}

ENV DEBIAN_FRONTEND=noninteractive

# enabled/disabled — controls whether to install linux-lib-rust-*-generic
# and splice it into the headers tree. Some older Ubuntus do ship the
# package but with a kernel-Rust API that's incompatible with our
# hello.rs (e.g. 6.8 doesn't auto-define __LOG_PREFIX in module!{}).
ARG KERNEL_RUST=enabled

# Base toolchain + kernel-build prerequisites. linux-headers-generic
# pulls in the right ABI version for the target Ubuntu release.
# bpftool packaging differs across releases:
#   26.04: a real `bpftool` package puts the binary at /usr/sbin/bpftool.
#   24.04: virtual; provided by linux-tools-X.Y-generic at
#          /usr/lib/linux-tools/<ver>/bpftool, with a /usr/sbin/bpftool
#          wrapper that calls `uname -r`. Inside a container `uname -r`
#          returns the HOST kernel, not the headers' kernel — so the
#          wrapper fails to find the right binary.
# Install both (whichever exists) then symlink the per-version binary
# directly into /usr/local/bin/bpftool so PATH lookups always resolve.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        zlib1g-dev \
        linux-headers-generic \
        pkg-config \
        ca-certificates \
        git \
 && (apt-get install -y --no-install-recommends bpftool 2>/dev/null \
     || apt-get install -y --no-install-recommends linux-tools-generic) \
 # Prefer the actual binary at /usr/lib/linux-tools/<ver>/bpftool over
 # /usr/sbin/bpftool — the latter is a wrapper script that calls
 # `uname -r` and fails inside a container. On 26.04 no
 # /usr/lib/linux-tools* dir exists, so the find returns empty and we
 # fall through to command -v, which there resolves to a real binary.
 && BPFTOOL=$(find /usr/lib/linux-tools* -type f -name bpftool 2>/dev/null | head -n1) \
 && [ -z "$BPFTOOL" ] && BPFTOOL=$(command -v bpftool) || true \
 && [ -n "$BPFTOOL" ] && [ -x "$BPFTOOL" ] && ln -sf "$BPFTOOL" /usr/local/bin/bpftool \
 && /usr/local/bin/bpftool version \
 && rm -rf /var/lib/apt/lists/*

# Kernel-Rust support: gated by KERNEL_RUST build-arg. When `enabled`,
# resolve the kernel ABI from the headers we just installed, install the
# matching linux-lib-rust-${KABI}-generic, and splice its rust/ tree
# into the headers. On Ubuntus that don't ship the package at all the
# install fails and we continue with rust support disabled (rust/Makefile
# detects via kernel.o and no-ops). When KERNEL_RUST=disabled we skip
# entirely — used for kernels where the package exists but its
# kernel-Rust API is incompatible with our hello.rs (e.g. 24.04/6.8).
RUN if [ "$KERNEL_RUST" != "enabled" ]; then \
        echo "[rootkat] kernel-Rust support: explicitly disabled (KERNEL_RUST=$KERNEL_RUST)"; \
    else \
        apt-get update \
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
            echo "[rootkat] kernel-Rust support: package not available for ABI ${KABI}" ; \
        fi \
     && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /work
