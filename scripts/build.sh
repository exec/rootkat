#!/usr/bin/env bash
# Build everything inside the rootkat Docker build container.
#
#   $UBUNTU_VERSION (env, default 26.04) selects the build env's Ubuntu
#   release. The container's kernel headers come from that release, so
#   the LKM ABI matches the QEMU cloud image at the same UBUNTU_VERSION.
#
#   For Fedora builds, set DISTRO=fedora and FEDORA_VERSION (default 42).
#   Optionally set KERNEL_VERSION to pin a specific kernel-devel version
#   (e.g. "6.14.0-63.fc42.x86_64") to match a specific cloud image kernel.
#
#   $BUILD_IMAGE_FORCE=1 forces a container rebuild.
#   $ROOTKAT_COMPONENTS (space-separated, default "lkm ebpf rust tests")
#   restricts which component subdirs are built. Set to "lkm" for a
#   fast release build that only produces rootkat.ko.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DISTRO="${DISTRO:-ubuntu}"
ARCH="${ARCH:-amd64}"

if [ "$DISTRO" = "fedora" ]; then
    # ARM64 Fedora builds: set ARCH=arm64 with DISTRO=fedora is not yet supported
    if [ "$ARCH" = "arm64" ]; then
        echo "[build] ERROR: ARCH=arm64 with DISTRO=fedora is not yet supported" >&2
        exit 1
    fi

    FEDORA_VERSION="${FEDORA_VERSION:-42}"
    KERNEL_VERSION="${KERNEL_VERSION:-}"
    IMAGE="rootkat-build:fedora-${FEDORA_VERSION}${KERNEL_VERSION:+-k${KERNEL_VERSION}}"

    if [ "${BUILD_IMAGE_FORCE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        echo "[build] Building Docker image $IMAGE..."
        docker buildx build --platform linux/amd64 --load \
            --build-arg "FEDORA_VERSION=${FEDORA_VERSION}" \
            --build-arg "KERNEL_VERSION=${KERNEL_VERSION}" \
            -t "$IMAGE" -f "$ROOT/build/Dockerfile.fedora" "$ROOT/build"
    fi

    TARGET="${1:-all}"
    COMPONENTS="${ROOTKAT_COMPONENTS:-lkm}"

    KDIR=$(docker run --rm "$IMAGE" bash -c \
        "ls -d /usr/src/kernels/${KERNEL_VERSION}* 2>/dev/null | head -1 || ls -d /usr/src/kernels/* | tail -1")

    BUILD_CMD=""
    for comp in $COMPONENTS; do
        BUILD_CMD="${BUILD_CMD}make -C ${comp} KDIR=${KDIR} ${TARGET} && "
    done
    BUILD_CMD="${BUILD_CMD%&& }"

    docker run --rm --platform linux/amd64 \
        -e ROOTKAT_I_UNDERSTAND=1 \
        -v "$ROOT":/work \
        -w /work \
        "$IMAGE" \
        bash -c "$BUILD_CMD"
else
    UBUNTU_VERSION="${UBUNTU_VERSION:-26.04}"

    if [ "$ARCH" = "arm64" ]; then
        IMAGE="rootkat-build:ubuntu-${UBUNTU_VERSION}-arm64"

        if [ "${BUILD_IMAGE_FORCE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
            echo "[build] Building Docker image $IMAGE..."
            # buildx + --load is required so Colima honors --platform.
            docker buildx build --platform linux/arm64 --load \
                --build-arg "UBUNTU_VERSION=${UBUNTU_VERSION}" \
                -t "$IMAGE" -f "$ROOT/build/Dockerfile.arm64" "$ROOT/build"
        fi

        TARGET="${1:-all}"
        COMPONENTS="${ROOTKAT_COMPONENTS:-lkm}"

        BTF_MOUNT=()
        if [ -e /sys/kernel/btf/vmlinux ]; then
            BTF_MOUNT=(-v /sys/kernel/btf:/sys/kernel/btf:ro)
        fi

        BUILD_CMD=""
        for comp in $COMPONENTS; do
            BUILD_CMD="${BUILD_CMD}make -C ${comp} ${TARGET} && "
        done
        BUILD_CMD="${BUILD_CMD%&& }"

        docker run --rm --platform linux/arm64 \
            -e ROOTKAT_I_UNDERSTAND=1 \
            ${BTF_MOUNT[@]+"${BTF_MOUNT[@]}"} \
            -v "$ROOT":/work \
            -w /work \
            "$IMAGE" \
            bash -c "$BUILD_CMD"
    else
        KERNEL_RUST="${KERNEL_RUST:-enabled}"
        IMAGE="rootkat-build:ubuntu-${UBUNTU_VERSION}-rust-${KERNEL_RUST}"

        if [ "${BUILD_IMAGE_FORCE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
            echo "[build] Building Docker image $IMAGE..."
            # buildx + --load is required so Colima honors --platform.
            docker buildx build --platform linux/amd64 --load \
                --build-arg "UBUNTU_VERSION=${UBUNTU_VERSION}" \
                --build-arg "KERNEL_RUST=${KERNEL_RUST}" \
                -t "$IMAGE" "$ROOT/build"
        fi

        TARGET="${1:-all}"
        COMPONENTS="${ROOTKAT_COMPONENTS:-lkm ebpf rust tests}"

        BTF_MOUNT=()
        if [ -e /sys/kernel/btf/vmlinux ]; then
            BTF_MOUNT=(-v /sys/kernel/btf:/sys/kernel/btf:ro)
        fi

        BUILD_CMD=""
        for comp in $COMPONENTS; do
            BUILD_CMD="${BUILD_CMD}make -C ${comp} ${TARGET} && "
        done
        BUILD_CMD="${BUILD_CMD%&& }"

        docker run --rm --platform linux/amd64 \
            -e ROOTKAT_I_UNDERSTAND=1 \
            ${BTF_MOUNT[@]+"${BTF_MOUNT[@]}"} \
            -v "$ROOT":/work \
            -w /work \
            "$IMAGE" \
            bash -c "$BUILD_CMD"
    fi
fi
