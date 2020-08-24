#!/bin/sh -x

cp /sys/kernel/security/ima/binary_runtime_measurements ./binary_runtime_measurements
./attest
