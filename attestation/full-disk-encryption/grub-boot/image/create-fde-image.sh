#!/bin/bash

set -e

THIS_DIR=$(dirname "$(readlink -f "$0")")
export FDE_DIR=${THIS_DIR}/../../../full-disk-encryption/grub-boot

INPUT_IMG=${FDE_DIR}/openEuler-24.03-LTS-SP1-cvm-aarch64.qcow2
OUTPUT_IMG=${FDE_DIR}/image/virtcca-cvm-openeuler-24.03-encrypted.qcow2
INPUT_HASH=${FDE_DIR}/hash.json

DRACUT_DIR=/usr/lib/dracut/modules.d/98fde

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

# Check whether the dirs are exited before mkdir
#
# args:
#   array of directory name - the dir list to be checked
check_dirs() {
    arr=("$@")
    is_exist=false
    for i in "${arr[@]}";
    do
        [ -d "$i" ] && { warn "$i is already existed" 1>&2 ; is_exist=true ;}
    done

    [[ $is_exist != true ]] || { error "Please delete existed directories"; }
}

# Display usage information
usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
Required
  -i <input image>                        Specify initial CVM image file
  -g <image measurement reference>        Specify measurement reference file of CVM image
  -a <attestation case>                   Specify local verifier for attestation (samples or rats-tls) 
Optional
  -o <output image>                       Default is virtcca-cvm-openeuler-24.03-encrypted.qcow2
EOM
}

process_args() {
    while getopts "i:g:a:o:h" option; do
        case "$option" in
        i) INPUT_IMG=$OPTARG;;
        g) INPUT_HASH=$OPTARG;;
        a) ATTEST_CASE=$OPTARG;;
        o)
            file_name=$(basename $OPTARG)
            if ! [[ -d $(dirname "$OPTARG") ]]; then
                error "No such directory"
            fi

            if [[ "$file_name" != *.qcow2 ]]; then
                error "Must be end with .qcow2"
            fi
            OUTPUT_IMG=$OPTARG
            ;;
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

    if [[ -z ${INPUT_IMG} ]]; then
        error "Please specify the input CVM image file via -i"
    else
        INPUT_IMG=$(readlink -f ${INPUT_IMG})
        if [[ ! -f ${INPUT_IMG} ]]; then
            error "File not exist ${INPUT_IMG}"
        fi
    fi

    if [ ${ATTEST_CASE} = "samples" ] || [ ${ATTEST_CASE} = "rats-tls" ]; then
        INITRD_DIR=${FDE_DIR}/initramfs/${ATTEST_CASE}
        ATTEST_DIR=${FDE_DIR}/attestation/${ATTEST_CASE}
        OUTPUT_HASH=${ATTEST_DIR}/hash.json
    else
        error "Please specify samples or rats-tls for attestation"
    fi

    ok "=================================================================="
    ok "Input image: ${INPUT_IMG}"
    ok "Output image: ${OUTPUT_IMG}"
    ok "Input hash: ${INPUT_HASH}"
    ok "Output hash: ${OUTPUT_HASH}"
    ok "Initramfs path: ${INITRD_DIR}"
    ok "Attest path: ${ATTEST_DIR}"
    ok "=================================================================="

    # Create output image
    cp ${INPUT_IMG} ${OUTPUT_IMG}

    # Create output hash json
    cp ${INPUT_HASH} ${OUTPUT_HASH}

    # Check and install packages needed
    HOST_PACKAGES=""
    if [[ -z "$(command -v qemu-img)" ]]; then
        HOST_PACKAGES+="qemu-img "
    fi

    if [[ -z "$(command -v virt-customize)" ]]; then
        HOST_PACKAGES+="guestfs-tools "
    fi
    
    if [[ -z "$(command -v openssl)" ]]; then
        HOST_PACKAGES+="openssl "
    fi

    if [[ -n ${HOST_PACKAGES} ]]; then
        dnf install -y ${HOST_PACKAGES}
    fi

    check_dirs /tmp/mnt/oldroot /tmp/mnt/backroot /tmp/mnt/newroot
}

# Create cmdline used for image update 
cat > "${FDE_DIR}/cmdline.sh" << "EOF"
#!/bin/bash

# Install required packages for guest
dnf install -y cryptsetup

# Update initramfs to include fde agent
INITRD_NAME=`ls /boot | grep initramfs-6.6.0* | head -1`
KERNEL_VERSION=$(echo ${INITRD_NAME} | sed -E 's/^initramfs-(.*)\.img$/\1/')
dracut --add "fde" --add-drivers "dm-crypt" --force /boot/${INITRD_NAME} ${KERNEL_VERSION}

# Configure kernel command line
GRUB_FILE=/boot/efi/EFI/openEuler/grub.cfg
sed -i 's/\(root=\)UUID=[^ ]*/\1\/dev\/mapper\/encroot/' ${GRUB_FILE}

# Update mount point of encrypted rootfs 
FSTAB_FILE=/etc/fstab
sed -i 's/\(UUID=[^ ]*\)\s\+\/\s\+ext4/\/dev\/mapper\/encroot \/ ext4/' ${FSTAB_FILE}

# Generate new reference measurements for initramfs and grub.cfg
sha256sum /boot/${INITRD_NAME} | awk "{print \$1}" > /root/initramfs_ref.txt
sha256sum ${GRUB_FILE} | awk "{print \$1}" > /root/grub_cfg_ref.txt

EOF

# Install fde agent into the initramfs of the CVM image
update_image() {
    info "Run setup scripts inside the CVM image. Please wait ..."
    if [ ${ATTEST_CASE} = "samples" ]; then
        # Install fde agent with samples into initramfs  
        virt-customize -a ${OUTPUT_IMG} \
            --mkdir ${DRACUT_DIR} \
            --copy-in ${INITRD_DIR}/module-setup.sh:${DRACUT_DIR} \
            --copy-in ${INITRD_DIR}/fde-agent.sh:${DRACUT_DIR} \
            --copy-in ${ATTEST_DIR}/virtcca-server:${DRACUT_DIR} \
            --run ${FDE_DIR}/cmdline.sh 
    else
        # Install fde agent with rats-tls into initramfs
        virt-customize -a ${OUTPUT_IMG} \
            --mkdir ${DRACUT_DIR} \
            --copy-in ${INITRD_DIR}/module-setup.sh:${DRACUT_DIR} \
            --copy-in ${INITRD_DIR}/fde-agent.sh:${DRACUT_DIR} \
            --copy-in ${ATTEST_DIR}/virtcca-server:${DRACUT_DIR} \
            --copy-in ${ATTEST_DIR}/lib:${DRACUT_DIR} \
            --run ${FDE_DIR}/cmdline.sh 
    fi
    if [ $? -eq 0 ]; then
        ok "Run setup scripts inside the CVM image"
    else
        error "Failed to setup CVM image"
    fi
    rm "${FDE_DIR}/cmdline.sh"
}

mount_rootfs() {
    # Create network block device
    if ! lsblk | grep "^nbd"; then
        modprobe nbd max_part=16
    fi
    
    # Locate free network block device
    NBD_DEV=""
    for NBD in /dev/nbd{0..16}; do
        if ! fuser ${NBD} >/dev/null 2>&1; then
            NBD_DEV=${NBD}
            break
        fi
    done
    if [ -z ${NBD_DEV} ]; then
        error "Failed to find free nbd device"
    fi

    # Map CVM image to network block device
    qemu-nbd --connect=${NBD_DEV} --format=qcow2 ${OUTPUT_IMG}
    partprobe
    BOOT=${NBD_DEV}p1
    ROOT=${NBD_DEV}p2
    info "NBD_DEV:${NBD_DEV} ROOT:${ROOT} BOOT:${BOOT}"

    # Mount CVM image and update golden measurements
    mkdir -p /tmp/mnt/oldroot
    mount ${ROOT} /tmp/mnt/oldroot
    GOLDEN_INITRD_MEASURE=$(cat /tmp/mnt/oldroot/root/initramfs_ref.txt)
    info "GOLDEN_INITRD_MEASURE: ${GOLDEN_INITRD_MEASURE}"
    sed -i "s/\"initramfs\": \".*\"/\"initramfs\": \"$GOLDEN_INITRD_MEASURE\"/" ${OUTPUT_HASH}
    GOLDEN_GRUBCFG_MEASURE=$(cat /tmp/mnt/oldroot/root/grub_cfg_ref.txt)
    info "GOLDEN_GRUBCFG_MEASURE: ${GOLDEN_GRUBCFG_MEASURE}"
    sed -i "s/\"grub.cfg\": \".*\"/\"grub.cfg\": \"$GOLDEN_GRUBCFG_MEASURE\"/" ${OUTPUT_HASH}
    rm /tmp/mnt/oldroot/root/initramfs_ref.txt
    rm /tmp/mnt/oldroot/root/grub_cfg_ref.txt

    # Backup rootfs data
    info "Backup rootfs data ..."
    mkdir -p /tmp/mnt/backroot
    rsync -aAX /tmp/mnt/oldroot/ /tmp/mnt/backroot/
    umount /tmp/mnt/oldroot
}

encryt_rootfs() {
    info "Rootfs encrypted adn opened using LUKS2 ..."
    # Setup rootfs to LUKS with cipher aes-xts-plain64
    echo -n "YES" | cryptsetup luksFormat ${ROOT} --type luks2 \
        --cipher aes-xts-plain64 \
        --key-file ${ATTEST_DIR}/rootfs_key.bin 
    # Open encrypted rootfs
    cryptsetup open ${ROOT} encroot --key-file ${ATTEST_DIR}/rootfs_key.bin
    ROOT_ENC=/dev/mapper/encroot
    info "ROOT_ENC:${ROOT_ENC} "
    cryptsetup status ${ROOT_ENC}
    
    info "Format rootfs and recover data ..."
    # Format rootfs with ext4
    mkfs.ext4 ${ROOT_ENC}
    # Recover rootfs data
    mkdir -p /tmp/mnt/newroot 
    mount ${ROOT_ENC} /tmp/mnt/newroot 
    rsync -aAX /tmp/mnt/backroot/ /tmp/mnt/newroot/
    umount /tmp/mnt/newroot
    ok "Now get the encrypted guest image for full disk encryption"
}

close_rootfs() {
    if ! [ -z ${ROOT_ENC} ]; then
        cryptsetup close ${ROOT_ENC} || true
    fi
    if ! [ -z ${NBD_DEV} ]; then
        qemu-nbd --disconnect ${NBD_DEV} || true
        if [[ ${NBD_DEV} == "/dev/nbd0" ]]; then
            fuser -kvm $NBD_DEV || true
            modprobe -r nbd ||true
        fi
    fi

    rm -rf /tmp/mnt/oldroot
    rm -rf /tmp/mnt/backroot
    rm -rf /tmp/mnt/newroot
    ok "Clean"
}

trap 'close_rootfs' EXIT

process_args "$@"

ok "Update Image: ===================================================="
update_image

ok "Mount Rootfs: ===================================================="
mount_rootfs

ok "Encrypt Rootfs: =================================================="
encryt_rootfs

ok "Close Rootfs: ===================================================="


