#!/bin/sh
musl-gcc -o exploit -static $1 
if [ ! -f ./exploit ]; then
    exit
fi
mv ./exploit ./initramfs/
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
cd ..
./launch.sh