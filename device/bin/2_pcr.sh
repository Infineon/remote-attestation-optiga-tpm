#!/bin/sh -x

tpm2_pcrread -o pcr
cp /sys/kernel/security/ima/binary_runtime_measurements ./binary_runtime_measurements
