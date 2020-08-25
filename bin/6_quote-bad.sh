#!/bin/sh -x

tpm2_quote -c 0x81000002 -q beefdeed -l sha1:10+sha256:10 -m quote -s sig
