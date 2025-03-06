#!/bin/bash

# called by dracut
check() {
    return 0
}

# called by dracut
depends() {
    echo network crypt dm
    return 0
}

# called by dracut
installkernel() {
    instmods dm_crypt
}

# called by dracut
install() {
    inst_multiple /usr/sbin/cryptsetup 
    find "$moddir/lib/rats-tls" \( -type f -o -type l \) | while read -r file; do
        relpath="${file#$moddir/lib/rats-tls/}"
        inst "$file" "/usr/lib/rats-tls/$relpath"
    done
    inst "$moddir/virtcca-server" /usr/bin/virtcca-server
    inst_hook pre-mount 90 "$moddir/fde-agent.sh"
}