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
        pkg-config \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
