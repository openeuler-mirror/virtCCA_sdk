#!/bin/bash
set -x

ROOT_DIR=$(cd $(dirname $0);pwd)

echo "build attestation sdk"
cd ${ROOT_DIR}/attestation/sdk
cmake -S . -B build
cmake --build build
