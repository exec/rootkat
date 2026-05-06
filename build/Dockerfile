# Ubuntu 26.04 LTS ships kernel 7.0 — match the target.
FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libelf-dev \
        libbpf-dev \
        bpftool \
        linux-headers-generic \
        pkg-config \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
