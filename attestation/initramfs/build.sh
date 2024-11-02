#!/bin/bash
INITRAMFS_PROJ_DIR=$(cd "$(dirname "$0")";pwd)
export ROOT=${INITRAMFS_PROJ_DIR}/../..
PACKAGE_DIR=${INITRAMFS_PROJ_DIR}/br2_external/package_patch
OUTPUT_DIR=${INITRAMFS_PROJ_DIR}/buildroot/output
APP_INSTALL_DIR=${INITRAMFS_PROJ_DIR}/br2_external/board/virtcca_qemu/rootfs_overlay
export BR2_EXTERNAL=${INITRAMFS_PROJ_DIR}/br2_external

# prepare to install rats-tls server
RATS_TLS_BIN=${INITRAMFS_PROJ_DIR}/../rats-tls/rats-tls/bin/rats-tls.tar.gz
if [ ! -f "${RATS_TLS_BIN}" ]; then
    echo "Cannot find ${RATS_TLS_BIN}"
    exit 1
fi

# clean
rm -rf ${APP_INSTALL_DIR}/tmp
rm -rf ${APP_INSTALL_DIR}/usr
mkdir -p ${APP_INSTALL_DIR}/tmp
mkdir -p ${APP_INSTALL_DIR}/usr/bin

# install rats-tls server
cd ${APP_INSTALL_DIR}/tmp
cp $RATS_TLS_BIN ./
tar -zxf rats-tls.tar.gz
cp -rf ${APP_INSTALL_DIR}/tmp/lib ${APP_INSTALL_DIR}/usr/
cp -rf ${APP_INSTALL_DIR}/tmp/virtcca-server ${APP_INSTALL_DIR}/usr/bin/

# clean up
rm -rf ${APP_INSTALL_DIR}/tmp
pushd ${INITRAMFS_PROJ_DIR}

# initramfs build process
if [ ! -d "buildroot" ]; then
    git clone https://gitlab.com/buildroot.org/buildroot.git -b 2024.02
fi
cd buildroot && make clean && make virtcca_qemu_defconfig && make
