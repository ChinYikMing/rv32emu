#!/usr/bin/bash

set -e

virtio_block_list=()

# The disk1.img should have all the files from the original rootfs.cpio
virtio_block_list+=("-x vblk:disk1.img")
for x in {1..29}; do
	echo $x
	virtio_block_list+=("-x vblk:disk1.img")
done

echo "${virtio_block_list[@]}"

# Boot via initramfs
# Need to build with INITRD_SIZE=32 since the rootfs.cpio is 30M
#build/rv32emu -k build/linux-image/Image -i build/linux-image/rootfs.cpio ${virtio_block_list[@]}

# Boot via virtio block device
# INITRD_SIZE does not matter anymore, more light weight when booting
build/rv32emu -k build/linux-image/Image -b 'earlycon console=ttyS0 root=/dev/vdaa' ${virtio_block_list[@]}
