# FileCrypt

FileCrypt is a Python-based file encryption and decryption tool. It uses the AES-256 encryption standard with a 96-bit IV for GCM. The tool is capable of encrypting and decrypting both individual files and entire directories.


## Features

- File and directory encryption and decryption
- Secure key generation
- Option to hide or keep file extensions in encrypted files
- Option to delete original files after encryption
- Detailed help for command usage

## Requirements

- Python 3
- cryptography library

## Installation

1. Clone the repository to your local machine.
2. Install the required Python libraries using pip:

```bash
pip install cryptography
```

## Usage

### Encryption

To encrypt a file or directory, use the following command:

```bash
filecrypt.py -e [2] [3] [4](optional) "FILE/FOLDER TO ENCRYPT" "PATH TO SAVE ENCRYPTED FILES AND KEY"(optional)
````
**Example:**
```bash
filecrypt.py -e -f/d -h/k -del "LocationOfFileToEncrypt" "optional folder to save encrypted file and key"
```

### Decryption
To decrypt a file or directory, use the following command:
```bash
filecrypt.py -d [2] [3](optional) "PATH OF ENCRYPTED FOLDER" "PATH OF KEY" "PATH TO SAVE DECRYPTED FILES"(optional)
```
**Example:**
```bash
filecrypt.py -d -f/d -del "pathToEncryptedFolder or Files" "path to key file" "optional folder to store decrypted files"
```

### Options

- `-e`: Encrypt
- `-d`: Decrypt
- `-f`: File
- `-h`: Hide file extension in encrypted file (e.g., myFile.txt -> myFile.enc)
- `-k`: Keep file extension in encrypted file (e.g., myFile.txt -> myFile~.txt)
- `-del`: Delete regular files after encryption (optional)


## Disclaimer

This tool is for educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Use it responsibly.


