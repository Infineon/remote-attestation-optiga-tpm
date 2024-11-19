#!/bin/sh -x
echo "Remember to update pcr according to config.cfg"
pcrs="sha256:10"
qualification=`xxd -p -c 9999 qualification`

cp /sys/kernel/security/ima/binary_runtime_measurements ./binary_runtime_measurements

tpm2_quote -c 0x81000002 -q $qualification -l $pcrs  -m quote -s sig
