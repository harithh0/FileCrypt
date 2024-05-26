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

For file encryption:

```bash
python filecrypt.py -e -f -h/k -del "LocationOfFileToEncrypt" "LocationToSaveEncryptedFile"
```

For directory encryption:

```bash
python filecrypt.py -e -d -h/k -del "LocationOfDirectoryToEncrypt" "LocationToSaveEncryptedFiles"
```

### Decryption

For file decryption:

```bash
python filecrypt.py -d -f -del "LocationOfEncryptedFile" "LocationOfKey"
```

For directory decryption:

```bash
python filecrypt.py -d -d -del "LocationOfEncryptedDirectory" "LocationOfKey"
```

## Options

- `-e`: Encrypt
- `-d`: Decrypt
- `-f`: File
- `-h`: Hide file extension in encrypted file (e.g., myFile.txt -> myFile.enc)
- `-k`: Keep file extension in encrypted file (e.g., myFile.txt -> myFile~.txt)
- `-del`: Delete regular files after encryption (optional)

## Note

The tool uses Python's garbage collection to attempt to clear memory after use, but this is not a guarantee that the memory is cleared immediately or that it's cleared in a secure manner. It's generally better to use libraries and constructs that are designed for secure handling of sensitive data.

## Disclaimer

This tool is for educational purposes only. The author is not responsible for any misuse or damage caused by this tool. Use it responsibly.