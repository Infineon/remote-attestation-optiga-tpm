#!/bin/sh -x

sudo chmod a+rwx /dev/tpm0
sudo chmod a+rwx /dev/tpmrm0
sudo chmod a+rw /sys/kernel/security/ima/binary_runtime_measurements

