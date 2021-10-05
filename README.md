# Introduction
Remote attestation is a mechanism to enable a remote system (server) to determine the integrity of a platform of another system (Raspberry Pi®). In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with TPM a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect the IMA measurement.

# Prerequisites

Hardware prerequisites:
- [Raspberry Pi® 4](https://www.raspberrypi.org/products/raspberry-pi-4-model-b/) or [Raspberry Pi® 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b/)
- [IRIDIUM9670 TPM2.0](https://www.infineon.com/cms/en/product/evaluation-boards/iridium9670-tpm2.0-linux/)\
  <img src="https://github.com/Infineon/remote-attestation-optiga-tpm/raw/master/media/IRIDIUM9670-TPM2.png" width="30%">

# Getting Started

In this repository, you will find attestation server and device (Raspberry Pi 3/4) reference implementations. For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/remote-attestation-optiga-tpm/raw/master/documents/tpm-appnote-ra.pdf).

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
