#!/bin/sh -x

cp /sys/kernel/security/ima/binary_runtime_measurements ./binary_runtime_measurements

tpm2_quote -c 0x81000002 -q beefdeed -l sha256:10 -m quote -s sig
