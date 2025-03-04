#!/bin/bash

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
ATTEST_SDK_DIR=${THIS_DIR}/../../../../attestation
FDE_DIR=${THIS_DIR}/../../../full-disk-encryption/grub-boot

ROOT_CERT_URL="https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000002&partNo=3001&mid=SUP_PKI"
SUB_CERT_URL="https://download.huawei.com/dl/download.do?actionFlag=download&nid=PKI1000000040&partNo=3001&mid=SUP_PKI"

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

# Display Usage information
usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
Required
  -a <attest case>              Specify local verifier for attestation, 
                                please input samples or rats-tls
EOM
}

process_args() {
    while getopts "a:h" option; do
        case "$option" in
        a) ATTEST_CASE=$OPTARG;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-$OPTARG'"
            usage
            exit 1
            ;;
        esac
    done

    if [ ${ATTEST_CASE} = "samples" ] || [ ${ATTEST_CASE} = "rats-tls" ]; then
        ATTEST_DIR=${FDE_DIR}/attestation/${ATTEST_CASE}
        mkdir -p ${ATTEST_DIR}
        ATTEST_CLIENT=${ATTEST_DIR}/virtcca-client
        ATTEST_SERVER=${ATTEST_DIR}/virtcca-server
        ROOT_CERT_FILE=${ATTEST_DIR}/root_cert.pem
        SUB_CERT_FILE=${ATTEST_DIR}/sub_cert.pem
        ROOTFS_KEY_FILE=${ATTEST_DIR}/rootfs_key.bin
    else
        error "Please specify samples or rats-tls for attestation"
    fi

    ok "=================================================================="
    ok "Attest path: ${ATTEST_DIR}"
    ok "Attest client: ${ATTEST_CLIENT}"
    ok "Attest server: ${ATTEST_SERVER}"
    ok "Root cert: ${ROOT_CERT_FILE}"
    ok "Sub cert: ${SUB_CERT_FILE}"
    ok "Rootfs key: ${ROOTFS_KEY_FILE}"
    ok "=================================================================="

     check_tools yum install tar cmake make git gcc
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
    # Copy samples to ${ATTEST_DIR}
    cp ${ATTEST_SDK_DIR}/samples/build/client ${ATTEST_CLIENT}
    cp ${ATTEST_SDK_DIR}/samples/build/server ${ATTEST_SERVER}
    cd ${ATTEST_DIR}
}

build_libcbor() {
    info "Build libcbor for rats-tls ..."
    cd ${ATTEST_SDK_DIR}/rats-tls
    if [ -d "libcbor/.git" ]; then
        info "rats-tls git repo already exists"
    else
        git clone https://github.com/PJK/libcbor.git
    fi
    cd libcbor
    cmake -S . -B build
    cd build
    make
    make install
    cd ${ATTEST_DIR}
}

build_rats_tls() {
    info "Build attestation rats-tls ..."
    cd ${ATTEST_SDK_DIR}/rats-tls
    if [ -d "rats-tls/.git" ]; then
        info "rats-tls git repo already exists. skip clone."
        cd rats-tls
    else 
        git clone https://github.com/inclavare-containers/rats-tls.git
        cd rats-tls
        git reset --hard 40f7b78403d75d13b1a372c769b2600f62b02692
        git apply ../*.patch
    fi
    bash build.sh -s -r -c -v gcc || error "compiles rats-tls error, please check rats-tls"
    # Copy rats-tls to ${ATTEST_DIR} and install envs
    cd ${ATTEST_DIR}
    cp ${ATTEST_SDK_DIR}/rats-tls/rats-tls/bin/rats-tls.tar.gz ${ATTEST_DIR}
    tar -zxf rats-tls.tar.gz
    cp -rf lib/rats-tls /usr/lib/
    export LD_LIBRARY_PATH=/usr/lib/rats-tls:$LD_LIBRARY_PATH
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

ok "Check which attestation cases will be built ..."

process_args "$@"

ok "Prepare attestation envs, include apps, certs ..."

info "Attestation apps re-build ..."
build_sdk
if [ ${ATTEST_CASE} = "samples" ]; then
    build_samples
else
    if [ ! -f /usr/local/lib64/libcbor.a ]; then
        build_libcbor
    fi
    build_rats_tls
fi

download_certfile

ok "Prepare rootfs key file for fde ..."

generate_rootfskey
