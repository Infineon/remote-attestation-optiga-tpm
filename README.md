# Introduction

Remote attestation is a mechanism that allows a remote system (e.g., a server) to verify the integrity of another system's platform (e.g., a Raspberry Pi). In Linux-based systems, a security feature called the Integrity Measurement Architecture (IMA) can be utilised to record platform measurements. Combined with a TPM (a hardware-based security module) and its attestation capabilities, this setup can be used to perform authentication and safeguard the IMA measurements.

---

# Table of Contents

- **[Prerequisites](#prerequisites)**
- **[Kernel Build Instructions](#kernel-build-instructions)**
- **[Kernel Modifications](#kernel-modifications)**
- **[Raspberry Pi Setup](#raspberry-pi-setup)**
  - **[Enable TPM and IMA](#enable-tpm-and-IMA)**
  - **[Install TPM Software](#install-tpm-software)**
  - **[Install Server Software](#install-server-software)**
  - **[Install Device Software](#install-device-software)**
- **[Operational Guide](#operational-guide)**
  - **[Running the Server](#running-the-server)**
  - **[TPM Provisioning](#tpm-provisioning)**
  - **[Running the Device](#running-the-device)**
- **[Operational Logic](#operational-logic)**
  - **[Attune](#attune)**
  - **[Atelic](#atelic)**
  - **[Attest](#attest)**
- **[License](#license)**

---

# Prerequisites

Prerequisites:
- A [Raspberry Pi 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/) or [Raspberry Pi 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b/)
- A microSD card (>=8GB) flashed with Raspberry Pi OS. Download the official image from [raspbian-2020-02-14](https://downloads.raspberrypi.org/raspbian/images/raspbian-2020-02-14/)
- One of the following TPM2.0 boards:
  - [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)
  - [OPTIGA™ TPM SLB 9672 RPI evaluation board](https://www.infineon.com/cms/en/product/evaluation-boards/optiga-tpm-9672-rpi-eval/)
- A host machine running Ubuntu 18.04 LTS.

---

# Kernel Build Instructions

This section covers rebuilding the Raspberry Pi Linux kernel from source.

Install required dependencies on the host machine:
```
$ sudo apt install git bc bison flex libssl-dev make libc6-dev libncurses5-dev libncurses5-dev
```

Install the toolchain and set the environment variable:
```
$ git clone https://github.com/raspberrypi/tools ~/tools
$ export PATH=$PATH:~/tools/arm-bcm2708/arm-linux-gnueabihf/bin
```

Download the Linux kernel source:
```
$ git clone -b rpi-4.19.y https://github.com/raspberrypi/linux ~/linux
$ cd ~/linux
$ git checkout raspberrypi-kernel_1.20200601-1
```

Build instructions:
> Before building, ensure the kernel source is modified. Refer to the [Kernel Modifications](#kernel-modifications) section for details.

1. For Raspberry Pi 3:
    ```
    # Prepare
    $ KERNEL=kernel7
    $ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2709_defconfig

    # Configure
    $ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- menuconfig

    # Build
    $ make -j$(nproc) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
    ```
2. For Raspberry Pi 4:
    ```
    # Prepare
    $ KERNEL=kernel7l
    $ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2711_defconfig

    # Configure
    $ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- menuconfig

    # Build
    $ make -j$(nproc) ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs
    ```

Transfer the kernel modules, kernel image, and device tree blobs to the SD card (ensure to replace `/dev/sdbX` and `/dev/sdbY` with the correct device identifiers):
```
$ mkdir mnt
$ mkdir mnt/fat32
$ mkdir mnt/ext4
$ sudo umount /dev/sdbX
$ sudo umount /dev/sdbY
$ sudo mount /dev/sdbX mnt/fat32
$ sudo mount /dev/sdbY mnt/ext4
$ sudo env PATH=$PATH make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- INSTALL_MOD_PATH=mnt/ext4 modules_install
$ sudo cp mnt/fat32/$KERNEL.img mnt/fat32/$KERNEL-backup.img
$ sudo cp arch/arm/boot/zImage mnt/fat32/$KERNEL.img
$ sudo cp arch/arm/boot/dts/*.dtb mnt/fat32/
$ sudo cp arch/arm/boot/dts/overlays/*.dtb* mnt/fat32/overlays/
$ sudo cp arch/arm/boot/dts/overlays/README mnt/fat32/overlays/
$ sudo umount mnt/fat32
$ sudo umount mnt/ext4
```

---

# Kernel Modifications

This section details the required modifications to the kernel source to enable the TPM and IMA mechanisms.

Enter menuconfig:
```
$ make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- menuconfig
```

Enable IMA mechanism:
```
Security options --->
[*] Enable different security models
[*] Integrity subsystem
[*]   Integrity Measurement Architecture(IMA)
        Default template (ima-sig) --->
        Default integrity hash algorithm (SHA256) --->
[*]     Enable multiple writes to the IMA policy
[*]     Enable reading back the current IMA policy
```

Make the following changes to initialize SPI and TPM before IMA activation.

Set TPM as a built-in module:
```
Device Drivers --->
Character devices --->
-*- TPM Hardware Support --->
<*>   TPM Interface Specification 1.3 Interface / TPM 2.0 FIFO Interface - (SPI)
```

Set SPI as a built-in module:
```
Device Drivers --->
[*] SPI support --->
      <*> BCM2835 SPI controller
```

Edit the file `drivers/clk/bcm/clk-bcm2835.c` and replace the following line:
```
postcore_initcall(__bcm2835_clk_driver_init);
```
With:
```
subsys_initcall(__bcm2835_clk_driver_init);
```

Modify line 122 of the file `security/integrity/ima/ima_policy.c`. The updated policy restricts IMA measurements to files owned by the root user and only when executed by root:
```
static struct ima_rule_entry default_measurement_rules[] __ro_after_init = {
    {.action = MEASURE, .func = BPRM_CHECK, .mask = MAY_EXEC,
    .uid = GLOBAL_ROOT_UID, .uid_op = &uid_eq,
    .fowner = GLOBAL_ROOT_UID, .fowner_op = &uid_eq,
    .flags = IMA_FUNC | IMA_MASK | IMA_UID | IMA_FOWNER},
};
```

---

# Raspberry Pi Setup

This section outlines the steps to install and enable all the necessary software and features on a Raspberry Pi.

## Enable TPM and IMA

Insert the SD card and boot into Raspberry Pi OS.

Open the file `/boot/config.txt` and add the following lines:
```
dtparam=spi=on
dtoverlay=tpm-slb9670
```

Open the file `/boot/cmdline.txt` and append the following to the existing line:
```
ima_policy=tcb
```

Reboot the system to apply the changes:
```
$ reboot
```

Run the following command to check if the TPM is active:
```
$ ls /dev | grep tpm
tpm0
tpmrm0
```

Run the following command to ensure IMA is active. The return value must be greater than 1:
```
$ sudo cat /sys/kernel/security/ima/runtime_measurements_count
```

Use the following command to view the active IMA policy and ensure it matches the expected configuration:
```
$ sudo cat /sys/kernel/security/ima/policy
dont_measure fsmagic=0x9fa0
dont_measure fsmagic=0x62656572
dont_measure fsmagic=0x64626720
dont_measure fsmagic=0x1021994
dont_measure fsmagic=0x1cd1
dont_measure fsmagic=0x42494e4d
dont_measure fsmagic=0x73636673
dont_measure fsmagic=0xf97cff8c
dont_measure fsmagic=0x43415d53
dont_measure fsmagic=0x27e0eb
dont_measure fsmagic=0x63677270
dont_measure fsmagic=0x6e736673
measure func=FILE_CHECK mask=^MAY_EXEC uid=0
```

Confirm that the IMA template (ima-sig) and the hash algorithm (SHA256) are set correctly by inspecting the runtime measurements:
```
$ sudo cat /sys/kernel/security/ima/ascii_runtime_measurements
10 <20 bytes of hash value> ima-sig sha1:<20 bytes of hash value> boot_aggregate
10 <20 bytes of hash value> ima-sig sha256:<32 bytes of hash value> <filename with path>
...
```

## Install TPM Software

This section covers building and installing TPM software from source.

Install the required dependencies:
```
$ sudo apt update
$ sudo apt -y install autoconf-archive libcmocka0 libcmocka-dev procps iproute2 \
  build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev autoconf \
  doxygen libgcrypt-dev libjson-c-dev libcurl4-gnutls-dev uuid-dev pandoc
```

Download, build, and install TPM software stack:
```
$ git clone https://github.com/tpm2-software/tpm2-tss.git
$ cd tpm2-tss
$ git checkout 2.4.0
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

Download, build, and install TPM tools:
```
$ git clone https://github.com/tpm2-software/tpm2-tools.git
$ cd tpm2-tools
$ git checkout 4.2
$ ./bootstrap
$ ./configure
$ make -j$(nproc)
$ sudo make install
$ sudo ldconfig
```

## Install Server Software

Install the required dependencies:
```
$ sudo apt install maven openjdk-9-jre
```

Download and build the server from source:
```
$ git clone https://github.com/infineon/remote-attestation-optiga-tpm ~/remote-attestation-optiga-tpm
$ cd ~/remote-attestation-optiga-tpm/server
$ mvn install
```

## Install Device Software

The device software consists of an application for communication with the server and step-by-step scripts for performing remote attestation.

Install the required dependencies:
```
$ sudo apt update
$ sudo apt install libconfig-dev libjson-c-dev libcurl4-gnutls-dev
```

Download and build the device software from source:
```
$ git clone https://github.com/infineon/remote-attestation-optiga-tpm ~/remote-attestation-optiga-tpm
$ cd ~/remote-attestation-optiga-tpm/device
$ make
```

---

# Operational Guide

This section outlines the steps required to perform remote attestation, presented in the following sequence:
1. [Running the Server](#running-the-server)
2. [TPM Provisioning](#tpm-provisioning)
3. [Running the Device](#running-the-device)

## Running the Server

Navigate to the server directory and start the server:
```
$ cd ~/remote-attestation-optiga-tpm/server/server/target
$ sudo java -jar server-0.0.1-SNAPSHOT.jar
```

The server will be ready for operation when you see the following message:
```
...
2020-06-10 22:37:51.856 INFO 12828 --- [ main]
o.s.m.s.b.SimpleBrokerMessageHandler : Started.

2020-06-10 22:37:52.414 INFO 12828 --- [ main]
o.s.b.w.embedded.tomcat.TomcatWebServer : Tomcat started on port(s): 443 (https) 80 (http) with context path ''

2020-06-10 22:37:52.418 INFO 12828 --- [ main]
com.ifx.server.ServerApplication : Started ServerApplication in 91.269 seconds (JVM running for 98.966)
```

Open the webpage (`https://localhost`) on Raspberry Pi OS using its built-in web browser.
- A warning message may appear due to the use of a self-signed certificate. This is expected.
- Bypass the warning and proceed to the website as usual.
- Note: On Raspberry Pi® 3, slower loading times are normal.

On the webpage, click "Start" on the upper menu bar to access the sign-in page. Use the following credentials to log in and view a self-explanatory dashboard:

| Username  | Password  |
|-----------|-----------|
| infineon  | password  |

## TPM Provisioning

Execute the following commands to perform a TPM clear:
```
$ sudo chmod a+rw /dev/tpm0
$ sudo chmod a+rw /dev/tpmrm0
$ tpm2_clear -c p
```

Create the Endorsement Key (EK) and store it as a persistent key:
```
$ tpm2_createek -G rsa -u ek.pub -c ek.ctx
$ tpm2_evictcontrol -C o -c ek.ctx 0x81010001
```

Create the Attestation Key (AK) and store it as a persistent key:
```
$ tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name
$ tpm2_evictcontrol -C o -c ak.ctx 0x81000002
```

Check the persistent handles in the TPM to ensure the keys are created successfully:
```
$ tpm2_getcap handles-persistent
- 0x81000002
- 0x81010001
```

## Running the Device

Navigate to the device directory:
```
$ cd ~/remote-attestation-optiga-tpm/device/bin
```

Execute the following scripts in sequence:

| Script              | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `0_prep.sh`       | Authorizes non-privileged access to the TPM device node.                   |
| `1_cleanup.sh`    | Erases non-essential files and restores the configuration file `config.cfg`. |
| `2_pcr.sh`        | Reads TPM PCRs and the IMA log.                                            |
| `3_attune.sh`     | Registers good platform measurements with a server.                       |
| `4_atelic.sh`     | Requests a server-encrypted challenge.                                     |
| `5_credential.sh` | Decrypts the challenge using `tpm2_activatecredential`.                   |
| `6_quote.sh`      | Generates a quote and a signature using `tpm2_quote`. Skip this if using `6_quote-bad.sh`. |
| `6_quote-bad.sh`  | Triggers a failure using an invalid challenge. Skip this if using `6_quote.sh`. |
| `7_attest.sh`     | Sends the quote, signature, and the latest IMA log to a server to perform attestation. |

---

# Operational Logic

This section explains the internal logic of the attestation system, breaking down the process into three main stages: Attune, Atelic, and Attest.

## Attune

**Attune** is the process of registering specific parameters with a server. These parameters serve as the "gold standard" or reference values, which are later used during the attestation stage to determine whether a device is in a healthy and trusted state. The parameters include:

| Parameter     | Description                                                                                             |
|---------------|---------------------------------------------------------------------------------------------------------|
| `sha1pcrs`    | List of PCR (Platform Configuration Register) indexes for the SHA1 PCR bank (e.g., `[9,10]`).          |
| `sha2pcrs`    | List of PCR indexes for the SHA256 PCR bank.                                                           |
| `ekCrt`       | Endorsement Key (EK) certificate issued by the TPM manufacturer. <br> Retrieve: <br> `tpm2_nvread 0x1c00002 -s 1184 --offset 0 -o ek.crt` <br> Inspect: <br> `openssl x509 -inform der -in ek.crt -text -noout` |
| `akPub`       | Attestation Key (AK) public key. <br> Retrieve: <br> `tpm2_readpublic -c 0x81000002 -o ak.pub`          |
| `pcrs`        | TPM PCR values. <br> Retrieve: <br> `tpm2_pcrread -o pcr` <br> PCRs not indicated by `sha1pcrs` or `sha2pcrs` are filtered out. |
| `imaTemplate` | A log of files measured by the Integrity Measurement Architecture (IMA). <br> Binary: `/sys/kernel/security/ima/binary_runtime_measurements` <br> Human-readable: `/sys/kernel/security/ima/ascii_runtime_measurements` |

The `ascii_runtime_measurements` file is an event log generated by the IMA subsystem at runtime. It contains a list of files measured by IMA. The hash value of each entry is sequentially extended to TPM PCR-10 (the default PCR index used by IMA). Since the Linux startup sequence is non-deterministic, the log may vary with each boot, resulting in different PCR values. Therefore, the sequence must be communicated to the server to ensure accurate verification.

## Atelic

**Atelic** is the process of requesting a challenge from a server. In response, the server generates a challenge and encrypts it using the TPM credential feature (`tpm2_makecredential`). Parameters Used by `tpm2_makecredential`:

| Parameter       | Description                                    |
|-----------------|------------------------------------------------|
| EK Public Key   | The Endorsement Key public key.                |
| AK Name         | A name derived from the Attestation Key public key blob. |
| Challenge       | A randomly generated string.                   |

The requester can decrypt the credential blob from the server and retrieve the challenge by following these steps:
```
$ tpm2_startauthsession --policy-session -S session.ctx
$ tpm2_policysecret -S session.ctx -c 0x4000000B
$ tpm2_activatecredential -c 0x81000002 -C 0x81010001 -i credential.blob -o qualification -P"session:session.ctx"
$ tpm2_flushcontext session.ctx
$ rm session.ctx
```

A challenge, also referred to as a qualification value, will be utilized in the following section.

## Attest

**Attest** is the process of requesting a server to perform remote attestation. The following parameters are included in the request:

| Parameter      | Description                                                                                 |
|----------------|---------------------------------------------------------------------------------------------|
| `quote`, `sig` | The quote and its signature can be generated using the following command: <br> `tpm2_quote -c 0x81000002 -q qualification -l sha1:9,10+sha256:9,10 -m quote -s sig` |
| `imaTemplate`  | The latest log from the Integrity Measurement Architecture (IMA), used for integrity verification. |

The server will verify the integrity and authenticity of the quote and its accompanying signature:
- **Quote**:<br>
  A detailed breakdown of a quote:
  | Parameter         | Description                                                     |
  |-------------------|-----------------------------------------------------------------|
  | PCR Bank (SHA1)   | Register indexes matching `attune.sha1pcrs`.                    |
  | PCR Bank (SHA256) | Register indexes matching `attune.sha2pcrs`.                    |
  | PCRs Digest       | Matches the computed digest (details below).                    |
  | Qualification     | Matches the value of `atelic.challenge`.                        |
  | AK Name           | Not implemented.                                                |
  | Firmware Version  | Not implemented.                                                |
  | TPM Clock         | Not implemented.                                                |

  PCRs Digest validation process:
  <ol type="1">
    <li>Validate Entries:<br>Verify that the entries in <code>attest.imaTemplate</code> are consistent with those in <code>attune.imaTemplate</code>.</li>
    <li>Compute PCR-10 Digest:<br>Generate a hash value for the <code>attest.imaTemplate</code>.</li>
    <li>Compute PCRs Digest:<br>Use the values from <code>attune.pcrs</code>, substituting the PCR-10 value with the computed hash, and then hash the modified set to derive the final digest.</li>
    <li>Verify Digest:<br>Confirm that the PCRs digest in the quote matches the computed digest.</li>
  </ol>

- **Signature**:<br>
  Verify the signature (`attest.sig`) using the Attestation Key (AK) public key (`attune.akPub`) and the quote message (`attest.quote`) to ensure its authenticity and integrity.

---

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
