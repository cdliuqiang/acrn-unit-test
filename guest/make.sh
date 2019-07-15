#!/usr/bin/env bash

make clean
./configure
echo "make x86/"$1".raw"
make x86/$1.raw
echo "scp x86/"$1".raw root@10.240.178.151:/boot/acrn-unit-test"
#scp /home/andy/intel/fangfang/acrn-hypervisor/hypervisor/build/acrn.32.out root@10.240.178.151:/boot/
scp /home/andy/intel/fangfang/acrn-hypervisor19/hypervisor/build/acrn.32.out  root@10.240.178.151:/boot/
scp x86/$1.raw root@10.240.178.151:/boot/acrn-unit-test

