#!/bin/sh -x

tpm2_readpublic -c 0x81000002 -o ak.pub
tpm2_nvread 0x1c00002 -o ek.crt

# Send AIK public key and expected PCRs value to server...
./attune
