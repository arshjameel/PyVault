# PyVault
## Description
A simple GUI password manager that provides basic encryption. It allows users to securely store and manage passwords in an SQL database, protected by a master password. Key features include:
* Master Password Protection: Secure your vault with a master password and generate a recovery key in case you forget it.
* Encryption: Passwords and sensitive data are encrypted using the [cryptography](https://github.com/pyca/cryptography) library.

## Installation
In order to use this program, we the need the following python libraries:

* cryptography: this is to encrypt your passwords.
* pyperclip: this is to provide clipboard functionality.

To install these libraries:
```
pip install cryptography pyperclip
```

## How to use
To run this program you have to clone this repository to your local machine using:
```
git clone https://github.com/arshjameel/PyVault.git
```
```
cd PyVault
```
Then run the program with:
```
python .\pyvault.py
```

## Notes
* After running the program, you should notice a file named 'pyvault.db' be generated. This file stores all information about your email accounts and any passwords associated with them, including the master password that you have set for yourself. All of this information is kept secure by encrypting it using the [cryptography](https://github.com/pyca/cryptography) library.
* It might bring one peace of mind to keep all passwords stored on your local machine, rather than some browser that might sell your information. However do note that this project is a work in progress and there are definitely better softwares available for this purpose. **It is strictly recommended to use this program in an academic manner.**
