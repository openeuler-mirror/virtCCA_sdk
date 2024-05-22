#!/bin/bash
set -x

ROOT_DIR=$(cd $(dirname $0);pwd)

function attestation() {
    echo "build attestation sdk"
    cd ${ROOT_DIR}/attestation/sdk
    cmake -S . -B build
    cmake --build build
}

function huk_derive() {
    echo "build huk derive key sdk"
    cd ${ROOT_DIR}/huk_derive/sdk
    cmake -S . -B build
    cmake --build build
}

case $1 in
    attest) attestation;;
    huk) huk_derive;;
    *)
        attestation
        huk_derive
        ;;
esac