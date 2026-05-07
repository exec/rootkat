# Ubuntu 26.04 LTS ships kernel 7.0 — match the target.
# Pinned to amd64 so Apple Silicon hosts cross-build correctly.
FROM --platform=linux/amd64 ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        zlib1g-dev \
        bpftool \
        linux-headers-generic \
        linux-lib-rust-7.0.0-15-generic \
        rustc \
        bindgen \
        rust-src \
        pkg-config \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/* \
    # `linux-headers-generic` ships only the rust/Makefile; the actual
    # kernel-rust crate artifacts (bindings, kernel.rmeta, etc.) come
    # from `linux-lib-rust-X-generic`. Splice the latter into the
    # headers tree so kbuild's M= path finds everything in one place.
    && rm -rf /usr/src/linux-headers-7.0.0-15-generic/rust \
    && ln -s /usr/src/linux-lib-rust-7.0.0-15-generic/rust \
            /usr/src/linux-headers-7.0.0-15-generic/rust

WORKDIR /work
