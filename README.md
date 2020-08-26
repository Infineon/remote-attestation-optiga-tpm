# Introduction
Remote attestation is a mechanism to enable a remote system (server) to determine the integrity of a platform of another system (Raspberry Pi®). In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with TPM a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect the IMA measurement.

For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/master/documents).

# Prerequisites
- Completing the steps in [server](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/server) branch.
- Device with TPM and IMA enabled. Please refer to the Application Note at [link](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/master/documents) 
- Device with software [tpm2-tss v2.4.0](https://github.com/tpm2-software/tpm2-tss) and [tpm2-tools v4.2](https://github.com/tpm2-software/tpm2-tools) installed

# Initialize TPM
Initialize the TPM before running the scripts in the following section.

Clear TPM:
```
$ sudo chmod a+rw /dev/tpm0
$ sudo chmod a+rw /dev/tpmrm0
$ tpm2_clear -c p
```
Initialize TPM:
```
$ tpm2_createek -G rsa -u ek.pub -c ek.ctx
$ tpm2_evictcontrol -C o -c ek.ctx 0x81010001
$ tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name
$ tpm2_evictcontrol -C o -c ak.ctx 0x81000002
```
After initialization, check if TPM returns the following:
```
$ tpm2_getcap handles-persistent
- 0x81000002
- 0x81010001
```

# Prepare for Build
Install the following dependencies.

```
$ sudo apt update
$ sudo apt install libconfig-dev libjson-c-dev libcurl4-gnutls-dev
```

# Build & Run Scripts
Build project:
```
$ make
```
Navigate to folder `bin`. Remember to launch the server before running scripts 0 to 7.

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
