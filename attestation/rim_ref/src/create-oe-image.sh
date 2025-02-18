#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

LOGFILE=/tmp/oe-guest-setup.txt
FORCE_RECREATE=false
TMP_GUEST_IMG_PATH="/tmp/openEuler-24.03-LTS-SP1-aarch64.qcow2"
SIZE=50
TMP_MOUNT_PATH="/tmp/vm_mount"

ok() {
    echo -e "\e[1;32mSUCCESS: $*\e[0;0m"
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    cleanup
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

info() {
    echo -e "\e[0;33mINFO: $*\e[0;0m"
}

check_tool() {
    [[ "$(command -v $1)" ]] || { error "$1 is not installed" 1>&2 ; }
}

usage() {
    cat <<EOM
Usage: $(basename "$0") [OPTION]...
  -h                        Show this help
  -f                        Force to recreate the output image
  -s                        Specify the size of guest image
  -v                        openEuler version (24.03, 24.09, ...)
  -p                        Set the password of guest image
  -o <output file>          Specify the output file, default is openEuler-<version>-aarch64.qcow2.
                            Please make sure the suffix is qcow2. Due to permission consideration,
                            the output file will be put into /tmp/<output file>.
EOM
}

process_args() {
    while getopts "v:o:s:n:u:p:r:fch" option; do
        case "$option" in
        o) GUEST_IMG_PATH=$(realpath "$OPTARG") ;;
        s) SIZE=${OPTARG} ;;
        f) FORCE_RECREATE=true ;;
        v) EULER_VERSION=${OPTARG} ;;
        p) GUEST_PASSWORD=${OPTARG} ;;
        h)
            usage
            exit 0
            ;;
        *)
            echo "Invalid option '-${OPTARG}'"
            usage
            exit 1
            ;;
        esac
    done

    if [[ -z "${EULER_VERSION}" ]]; then
        error "Please specify the openEuler release by setting EULER_VERSION or passing it via -v"
    fi

    # generate variables
    ORIGINAL_IMG="openEuler-${EULER_VERSION}-aarch64.qcow2"
    ORIGINAL_IMG_PATH=$(realpath "${SCRIPT_DIR}/${ORIGINAL_IMG}")

    # output guest image, set it if user does not specify it
    if [[ -z "${GUEST_IMG_PATH}" ]]; then
        GUEST_IMG_PATH=$(realpath "openEuler-${EULER_VERSION}-cvm-aarch64.qcow2")
    fi

    if [[ "${ORIGINAL_IMG_PATH}" == "${GUEST_IMG_PATH}" ]]; then
        error "Please specify a different name for guest image via -o"
    fi

    if [[ ${GUEST_IMG_PATH} != *.qcow2 ]]; then
        error "The output file should be qcow2 format with the suffix .qcow2."
    fi
}

download_image() {
    # Get the checksum file first
    if [[ -f ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum" ]]; then
        rm ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum"
    fi

    OFFICIAL_openEuler_IMAGE="https://repo.openeuler.org/openEuler-${EULER_VERSION}/virtual_machine_img/aarch64/"
    wget "${OFFICIAL_openEuler_IMAGE}/openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum" -O ${SCRIPT_DIR}/openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum --no-check-certificate

    while :; do
        # Download the image if not exists
        if [[ ! -f ${ORIGINAL_IMG_PATH} ]]; then
            wget -O ${ORIGINAL_IMG_PATH}.xz ${OFFICIAL_openEuler_IMAGE}/${ORIGINAL_IMG}.xz --no-check-certificate
        fi

        # calculate the checksum
        download_sum=$(sha256sum ${ORIGINAL_IMG_PATH}.xz | awk '{print $1}')
        found=false
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" == *"$ORIGINAL_IMG"* ]]; then
                if [[ "${line%% *}" != ${download_sum} ]]; then
                    echo "Invalid download file according to sha256sum, re-download"
                    rm ${ORIGINAL_IMG_PATH}
                else
                    ok "Verify the checksum for openEuler image."
                    xz -dk ${ORIGINAL_IMG_PATH}.xz
                    return
                fi
                found=true
            fi
        done < ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum"
        if [[ $found != "true" ]]; then
            echo "Invalid SHA256SUM file"
            exit 1
        fi
    done
}

resize_guest_image() {
    qemu-img resize ${TMP_GUEST_IMG_PATH} +${SIZE}G
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --run-command 'echo "sslverify=false" >> /etc/yum.conf' \
        --install cloud-utils-growpart \
        --run-command 'growpart /dev/sda 2' \
        --run-command 'resize2fs /dev/sda2' \
        --run-command 'systemctl mask pollinate.service'
    if [ $? -eq 0 ]; then
        ok "Resize the guest image to ${SIZE}G"
    else
        error "Failed to resize guest image to ${SIZE}G"
    fi
}

create_guest_image() {
    if [ ${FORCE_RECREATE} = "true" ]; then
        rm -f ${ORIGINAL_IMG_PATH}
    fi

    download_image

    install -m 0777 ${ORIGINAL_IMG_PATH} ${TMP_GUEST_IMG_PATH}
    if [ $? -eq 0 ]; then
        ok "Copy the ${ORIGINAL_IMG} => ${TMP_GUEST_IMG_PATH}"
    else
        error "Failed to copy ${ORIGINAL_IMG} to /tmp"
    fi

    resize_guest_image
}

setup_guest_image() {
    info "Run setup scripts inside the guest image. Please wait ..."
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
       --run-command 'grub2-mkimage -d /usr/lib/grub/arm64-efi -O arm64-efi --output=/boot/efi/EFI/openEuler/grubaa64.efi --prefix="(,msdos1)/efi/EFI/openEuler" fat part_gpt part_msdos linux tpm' \
       --run-command 'cp -f /boot/efi/EFI/openEuler/grubaa64.efi /boot/EFI/BOOT/BOOTAA64.EFI' \
       --run-command "sed -i '/linux.*vmlinuz-6.6.0/ s/$/ ima_rot=tpm cma=64M virtcca_cvm_guest=1 cvm_guest=1 swiotlb=65536,force loglevel=8/' /boot/efi/EFI/openEuler/grub.cfg" \
       --run-command "sed -i '/^GRUB_CMDLINE_LINUX=/ s/\"$/ ima_rot=tpm cma=64M virtcca_cvm_guest=1 cvm_guest=1 swiotlb=65536,force loglevel=8\"/' /etc/default/grub"
    if [ $? -eq 0 ]; then
        ok "Run setup scripts inside the guest image"
    else
        error "Failed to setup guest image"
    fi
}

set_guest_password() {
    if [[ -z "${GUEST_PASSWORD}" ]]; then
        GUEST_PASSWORD=openEuler12#$
    fi
    virt-customize -a ${TMP_GUEST_IMG_PATH} --password root:password:${GUEST_PASSWORD}
}

measure_guest_image() {
    guestunmount ${TMP_MOUNT_PATH}
    gcc measure_pe.c -o MeasurePe -lcrypto
    mkdir -p ${TMP_MOUNT_PATH}
    guestmount -a ${TMP_GUEST_IMG_PATH} -i ${TMP_MOUNT_PATH}
    if [ $? -ne 0 ]; then
        echo "Failed to mount the virtual machine image."
        exit 1
    fi

    BOOT_EFI_PATH="${TMP_MOUNT_PATH}/boot/EFI/BOOT/BOOTAA64.EFI"
    if [ ! -f "${BOOT_EFI_PATH}" ]; then
        echo "BOOTAA64.EFI file not found in the virtual machine image."
        guestunmount ${TMP_MOUNT_PATH}
        exit 1
    fi
    sha_grub=$(./MeasurePe /tmp/vm_mount/boot/EFI/BOOT/BOOTAA64.EFI | awk -F"SHA-256 = " '{print $2}')
    guestunmount ${TMP_MOUNT_PATH}
    virt-customize -a ${TMP_GUEST_IMG_PATH} \
        --run-command "gunzip -c /boot/vmlinuz-6.6.0-72.0.0.76.oe2403sp1.aarch64 > /boot/vmlinuz-6.6.0-72.0.0.76.oe2403sp1.aarch64.uncompressed" \
        --run-command '
            sha_grub_cfg=$(sha256sum /boot/efi/EFI/openEuler/grub.cfg | awk "{print \$1}")
            sha_initramfs=$(sha256sum /boot/initramfs-6.6.0-72.0.0.76.oe2403sp1.aarch64.img | awk "{print \$1}")
            sha_kernel=$(sha256sum /boot/vmlinuz-6.6.0-72.0.0.76.oe2403sp1.aarch64.uncompressed | awk "{print \$1}")
            printf "{\n    \"grub\": \"%s\",\n    \"grub.cfg\": \"%s\",\n    \"kernel\": \"%s\",\n    \"initramfs\": \"%s\",\n    \"hash_alg\": \"sha-256\"\n}" "$sha_grub_cfg" "$sha_grub_cfg" "$sha_kernel" "$sha_initramfs" > /root/hash.json
        '
    virt-cat -a ${TMP_GUEST_IMG_PATH} /root/hash.json > hash.json
    jq --arg sha_grub "$sha_grub" '.["grub"] = $sha_grub' hash.json > temp.json && mv temp.json hash.json

}

cleanup() {
    if [[ -f ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum" ]]; then
        rm ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz.sha256sum"
    fi
	
    if [[ -f ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz" ]]; then
        rm ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2.xz"
		rm ${SCRIPT_DIR}/"openEuler-${EULER_VERSION}-aarch64.qcow2"
    fi
    info "Cleanup!"
}

rm -f ${LOGFILE}
echo "=== cvm guest image generation === " > ${LOGFILE}

# install required tools
yum install -y libguestfs-tools virt-install qemu-img genisoimage guestfs-tools cloud-utils-growpart jq &>> ${LOGFILE}

check_tool qemu-img
check_tool virt-customize
check_tool virt-install


info "Installation of required tools"

process_args "$@"

create_guest_image

setup_guest_image

set_guest_password

measure_guest_image

cleanup

mv ${TMP_GUEST_IMG_PATH} ${GUEST_IMG_PATH}

ok "cvm guest image : ${GUEST_IMG_PATH}"