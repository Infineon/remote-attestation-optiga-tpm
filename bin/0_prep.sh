#!/bin/sh -x

sudo chmod a+rw /dev/tpm0
sudo chmod a+rw /dev/tpmrm0
sudo chmod a+rw /sys/kernel/security/ima/binary_runtime_measurements

