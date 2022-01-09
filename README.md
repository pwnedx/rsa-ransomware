
![Logo](https://i.ibb.co/GkrJkfS/rsa.png)


# RSA-Ransomware

Easy to use C# .NET Core ransomware based on RSA & AES cryptography.

This product has been created for educational purposes only, the developer does not assume the responsibility for any harm caused by the misuse
of this code.

## Features

- Asymmetrical encryption
- Multiple OS compatibility

## FAQ

#### How does it work?

Once started on the target system, the software will automatically encrypt the data stored within the hard-coded target directories.

In order to use the software completely, you will need your own [RSA Keypair](https://www.ibm.com/docs/en/zos/2.1.0?topic=keys-rsa-private-public), inserting your pair's public key inside the proper variable.

The software will generate a random 16-char string, used to encrypt every file via AES, once the encryption is completed, the 16-char string will be encrypted using your RSA public key (Resulting in the ID). The 16-char string used to encrypt will be lost and to recover it you will need to decrypt the target ID with your RSA Keypair's private key.

#### Is there a decryption software?

Not yet, but you may create your own.


## Installation & Execution

In order to run the software on a system, the package "mono-complete" needs to be installed, in order to compile/execute .net code.

```bash
  sudo apt install mono-complete
  mcs code.cs
  ./code.exe
```
    
## Support

No support is going to be given regarding this project.


## Authors

- [@pwnedx](https://www.github.com/pwnedx)

