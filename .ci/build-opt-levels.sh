#!/usr/bin/env bash

# Build the emulator at the boundary optimization levels.
#
# -O0 catches code that only compiles once the optimizer folds it away, -O2 is
# what everyone actually ships, and -Ofast turns on the relaxed floating-point
# and aliasing rules that the softfloat and JIT paths must still survive.
#
# Usage:
#   .ci/build-opt-levels.sh <defconfig> [OPT_LEVEL...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/common.sh"

set -e -u -o pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <defconfig> [OPT_LEVEL...]" >&2
    exit 2
fi

DEFCONFIG=$1
shift

OPT_LEVELS=("$@")
if [ "${#OPT_LEVELS[@]}" -eq 0 ]; then
    OPT_LEVELS=(-O0 -O2 -Ofast)
fi

for opt_level in "${OPT_LEVELS[@]}"; do
    echo "Building ${DEFCONFIG} with OPT_LEVEL=${opt_level}"

    # cleanconfig, not distclean: it drops the objects and the configuration,
    # which is all a flag change needs, while leaving the prebuilt artifacts the
    # job setup just downloaded in place.
    if ! (make cleanconfig && make "${DEFCONFIG}" && make OPT_LEVEL="${opt_level}" ${PARALLEL}); then
        print_error "${DEFCONFIG} build failed with OPT_LEVEL=${opt_level}"
        exit 1
    fi
done
