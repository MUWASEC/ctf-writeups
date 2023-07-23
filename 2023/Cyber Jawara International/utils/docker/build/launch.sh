#!/bin/bash
/usr/bin/qemu-system-x86_64 \
	-kernel ./bzImage \
	-m 256M \
	-initrd ./initramfs.cpio.gz \
	-nographic \
	-monitor none \
	-no-reboot \
	-cpu kvm64,+smep\
    -s \
	-append "console=ttyS0 kaslr kpti=1 quiet panic=1 oops=panic" \
    -smp cores=2
