# Introduction

Remote attestation is a mechanism to enable a remote system (server) to determine the health/integrity of a platform of another system. In a Linux-based system, a security feature known as the Integrity Measurement Architecture (IMA) can be used to capture platform measurements. Together with Infineon OPTIGA™ TPM (Trusted Platform Module), a hardware-based security and its set of attestation features, it can be used to perform authentication and to protect IMA measurements; consequently, raises the trust level of remote attestation.

For detailed setup and information, please find the Application Note at [link](tobeupdated).

# Build

Install Maven:
```
$ sudo apt install maven
```
Build project:
 ```
 $ mvn install
``` 
JAR file location: `server/target/server-0.0.1-SNAPSHOT.jar`

# Run

Install openJDK:
```
$ sudo apt-get install openjdk-9-jre
```
Run server. On Raspberry Pi you may need root privilege to access port 80/443.
```
$ java -jar server-0.0.1-SNAPSHOT.jar
```

# License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
