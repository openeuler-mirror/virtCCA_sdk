#!/bin/bash

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
ATTEST_SDK_DIR=${THIS_DIR}/../../../../attestation
FDE_DIR=${THIS_DIR}/../../../full-disk-encryption/grub-boot
ATTEST_DIR=${FDE_DIR}/attestation

ROOT_CERT_FILE=${ATTEST_DIR}/root_cert.pem
ROOT_CERT_URL="https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000002&partNo=3001&mid=SUP_PKI"
SUB_CERT_FILE=${ATTEST_DIR}/sub_cert.pem
SUB_CERT_URL="https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000040&partNo=3001&mid=SUP_PKI"
ROOTFS_KEY_FILE=${ATTEST_DIR}/rootfs_key.bin
ATTEST_CLIENT=${ATTEST_DIR}/client
ATTEST_SERVER=${ATTEST_DIR}/server

info() {
    echo -e "\e[1;33m$*\e[0;0m"
}

ok() {
    echo -e "\e[1;32mSUCCESS: $*\e[0;0m"
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

# Check whether the tools are installed from the provided list
#
# args:
#   array of tool name  -    the name list to be checked
check_tools() {
    arr=("$@")
    is_missing=false
    for i in "${arr[@]}";
    do
        [[ "$(command -v "$i")" ]] || { info "MISSING: $i is not installed" 1>&2 ; is_missing=true ;}
    done

    [[ $is_missing != true ]] || { error "Please install missing tools"; }
}

build_sdk() {
    info "Build attestation sdk ..."
    cd ${ATTEST_SDK_DIR}/sdk
    cmake -S . -B build
    cmake --build build
    cmake --install build
    cd ${ATTEST_DIR}
}

build_samples() {
    info "Build attestation samples ..."
    cd ${ATTEST_SDK_DIR}/samples
    cmake -S . -B build
    cmake --build build
    cp ${ATTEST_SDK_DIR}/samples/build/client ${ATTEST_CLIENT}
    cp ${ATTEST_SDK_DIR}/samples/build/server ${ATTEST_SERVER}
    cd ${ATTEST_DIR}
}

download_certfile() {
    # Download root cert pem file
    if [[ ! -f ${ROOT_CERT_FILE} ]] ; then
        info "Root cert does not exist, re-download ..."
        wget -O ${ROOT_CERT_FILE} ${ROOT_CERT_URL}
    fi
    # Download sub cert pem file
    if [[ ! -f ${SUB_CERT_FILE} ]] ; then
        info "Sub cert does not exist, re-download ..."
        wget -O ${SUB_CERT_FILE} ${SUB_CERT_URL}
    fi
}

generate_rootfskey() {
    # Generate rootfs key file
    if [[ ! -f ${ROOTFS_KEY_FILE} ]] ; then
        info "rootfs key file does not exist, re-generate ..."
        openssl rand -out ${ROOTFS_KEY_FILE} 32
    fi
}

ok "Prepare attestation envs, include apps, certs ..."

if [[ ! -f ${ATTEST_CLIENT} || ! -f ${ATTEST_SERVER} ]] ; then
    info "Attestation apps do not exist, re-build ..."
    check_tools yum install tar cmake make git gcc
    build_sdk
    build_samples
fi

download_certfile

ok "Prepare rootfs key file for fde ..."

generate_rootfskey
