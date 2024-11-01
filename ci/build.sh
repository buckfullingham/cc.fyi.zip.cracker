#!/usr/bin/env bash

BUILD_ROOT="${BUILD_ROOT:-"$(readlink -f "$(dirname "$0")/..")"}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR="${BUILD_DIR:-cmake-build-$(echo "$BUILD_TYPE" | tr '[:upper:]' '[:lower:]')}"

# exit on error
set -e

# check python, pip & cmake are installed
python3 --version
pip3 --version
cmake --version

# setup python / conan env
trap '/bin/rm -rf $VENV' EXIT
VENV="$(mktemp -d /tmp/XXXXXX)"
python3 -m venv "$VENV"
source "$VENV/bin/activate"
pip3 install -r "$BUILD_ROOT/ci/requirements.txt"
conan profile detect

# build/install cc.fyi.common
cd "$BUILD_ROOT/cc.fyi.common"
conan create -s build_type="$BUILD_TYPE" -s compiler.cppstd=23 -s compiler.libcxx=libstdc++11 --build missing .

# install dependencies
cd ..
conan install -of "$BUILD_DIR" -s build_type="$BUILD_TYPE" -s compiler.cppstd=23 -s compiler.libcxx=libstdc++11 --build missing .

# configure build
cmake --preset conan-release -S "$BUILD_ROOT" -B "$BUILD_ROOT/$BUILD_DIR"
cd "$BUILD_DIR"

# put dependencies' dll's on LD_LIBRARY_PATH etc
source conanrun.sh

# build
cmake --build . --parallel

# run tests
ctest .
