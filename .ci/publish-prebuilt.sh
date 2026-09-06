#!/usr/bin/env bash

# Publish build outputs as a release on the rv32emu-prebuilt repository.
#
# The tag encodes the date and the source commit, which is what the artifact
# fetchers in mk/artifact.mk match against.
#
# Usage:
#   .ci/publish-prebuilt.sh <tag-suffix> <file>...
#
# Files are taken relative to the current directory, so the caller can stay in
# whatever staging directory it built the tarball in.
#
# Environment:
#   GH_TOKEN: token with write access to sysprog21/rv32emu-prebuilt.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

set -e -u -o pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <tag-suffix> <file>..." >&2
    exit 2
fi

PREBUILT_REPO=sysprog21/rv32emu-prebuilt
SUFFIX=$1
shift

RELEASE_TAG="$(date +'%Y.%m.%d')-$(git -C "${REPO_DIR}" rev-parse --short HEAD)-${SUFFIX}"

# Create as a draft, then publish once every asset is up. A plain release is
# visible to the artifact fetchers the moment it exists, so publishing first
# leaves a window where they resolve this tag and then fail to download, or take
# an incomplete set.
gh release create --draft --latest=false "${RELEASE_TAG}" \
    --repo "${PREBUILT_REPO}" \
    --title "${RELEASE_TAG}"
gh release upload "${RELEASE_TAG}" "$@" --repo "${PREBUILT_REPO}"

# --latest=false again on publish: the flag set at creation does not survive the
# draft transition, and these are dated prebuilt drops, not the release a
# visitor to the repository should land on.
gh release edit "${RELEASE_TAG}" --draft=false --latest=false --repo "${PREBUILT_REPO}"
