#!/usr/bin/env bash

make clean
./configure
echo "make x86/"$1".raw"
make x86/$1.raw
echo "scp x86/"$1".elf root@10.240.178.146:/boot/acrn-unit-test"
scp x86/$1.elf root@10.240.178.151:/boot/acrn-unit-test-native

