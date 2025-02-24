#!/bin/sh

dhclient eth0
IP_ADDR=$(ip addr show eth0 | sed -n '/inet /s/.*inet \([0-9.]\+\).*/\1/p')

echo "fde: Running attestation in pre-mount phase..." > /dev/console
echo "fde: CVM IP Address: ${IP_ADDR} ..." > /dev/console
echo "fde: Attestation server port: 7220 ..." > /dev/console
/usr/bin/server -i ${IP_ADDR} -p 7220 -k 
sleep 1

echo "fde: Running rootfs decryption in initramfs..." > /dev/console
cryptsetup open /dev/vda2 encroot --key-file /root/rootfs_key.bin

