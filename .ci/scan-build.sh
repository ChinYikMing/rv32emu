#!/usr/bin/env bash

# Run the Clang static analyzer over an interpreter and a JIT build.
#
# --status-bugs makes scan-build exit non-zero on any report, which is what
# turns this into a gate rather than a report nobody reads.
#
# Usage:
#   .ci/scan-build.sh [defconfig...]     (default: defconfig jit_defconfig)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

set -e -u -o pipefail

LLVM_VERSION=$(cat "${SCRIPT_DIR}/llvm-version")

# The analyzer never runs the emulator, so it does not need a real prebuilt
# release; mk/artifact.mk only wants the variable to be non-empty.
export LATEST_RELEASE="${LATEST_RELEASE:-dummy}"

DEFCONFIGS=("$@")
if [ "${#DEFCONFIGS[@]}" -eq 0 ]; then
    DEFCONFIGS=(defconfig jit_defconfig)
fi

for defconfig in "${DEFCONFIGS[@]}"; do
    case "${defconfig}" in
        jit_defconfig) jit=1 ;;
        *) jit=0 ;;
    esac

    echo "Running scan-build over ${defconfig}"
    make distclean
    make "${defconfig}"
    "scan-build-${LLVM_VERSION}" -v -o ~/scan-build \
        --status-bugs \
        --use-cc="clang-${LLVM_VERSION}" \
        --force-analyze-debug-code \
        --show-description \
        -analyzer-config stable-report-filename=true \
        -enable-checker valist,nullability \
        make ENABLE_EXT_F=0 ENABLE_SDL=0 "ENABLE_JIT=${jit}"
done
