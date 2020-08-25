#!/bin/sh -x

tpm2_readpublic -c 0x81000002 -o ek.pub

# Send EK public key
./atelic
