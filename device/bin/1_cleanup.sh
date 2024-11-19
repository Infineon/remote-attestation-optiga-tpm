#!/bin/sh -x

rm -f credential.blob ek.crt ek.pub ak.pub ak.name pcr quote sig qualification config.cfg binary_runtime_measurements
cp ../config.cfg ./config.cfg

