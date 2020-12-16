# Introduction
Remote attestation is a mechanism to enable a remote system (server) to determine the integrity of a platform of another system (Raspberry Pi®). In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with TPM a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect the IMA measurement.

In this repository, you will find attestation server and device (Raspberry Pi 3/4) reference implementations. For detailed setup and information, please find the Application Note at [link](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/master/documents).

# Repository Directions
- Server repo, please switch to [server](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/server) branch.
- Device repo, please switch to [device](https://github.com/Infineon/remote-attestation-optiga-tpm/tree/device) branch.

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
