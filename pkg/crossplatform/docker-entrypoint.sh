#!/bin/bash
#
# A docker entrypoint script to build haulage package
set -e

# Assign input parameters to more descriptive variables

# Distro version is distinct from codename to ensure the distro version always
# compares newer as new versions are released. For example, debian9 < debian10,
# while stretch (debian9's codename) is not < buster (debian10's).
DISTRO_RELEASE_VERSION=$1
DISTRO_RELEASE_CODENAME=$2
OUT_USER=$3

# Buildthe package
DISTRO_RELEASE_VERSION=$DISTRO_RELEASE_VERSION make package_arm64 package_x86_64

# Copy the built packages to the mounted output volume
mkdir -p /build-volume/"${DISTRO_RELEASE_CODENAME}"
mv build/*.deb /build-volume/"${DISTRO_RELEASE_CODENAME}"

if test -z "$OUT_USER"
then
    echo "No output user set, leaving as container user (likely root)"
else
    chown --recursive $OUT_USER /build-volume/"${DISTRO_RELEASE_CODENAME}"
    chgrp --recursive $OUT_USER /build-volume/"${DISTRO_RELEASE_CODENAME}"
fi