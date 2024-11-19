#!/bin/sh -x

tpm2_startauthsession --policy-session -S session.ctx
tpm2_policysecret -S session.ctx -c 0x4000000B
tpm2_activatecredential -c 0x81000002 -C 0x81010001 -i credential.blob -o qualification -P"session:session.ctx"
tpm2_flushcontext session.ctx
rm session.ctx

