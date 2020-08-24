# Introduction

Remote attestation is a mechanism to enable a remote system (server) to determine the health/integrity of a platform of another system. In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with Infineon OPTIGA™ TPM (Trusted Platform Module), a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect IMA measurements; consequently, raises the trust level of remote attestation.

Please find the Application Note at [link](tobeupdated).

# Prepare for Build

Install following dependencies.

## libcurl
libcurl can be installed directly via:

```
$ sudo apt install curl
```

## libjson-c
libjson-c download and build:

```
$ git clone https://github.com/json-c/json-c
$ sudo apt install cmake
$ mkdir json-c-build
$ cd json-c-build
$ cmake ../json-c
$ make
$ make install
```

## libconfig
libconfig can be installed directly via:

```
$ sudo apt install libconfig-dev
```

# Initialize TPM

Clear TPM:
```
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

# Build & Run

Build project:
```
$ make
```
Navigate to folder `bin`. Remember to launch server before running scripts 0 to 7.

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
