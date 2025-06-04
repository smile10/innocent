# Innocent – Educational Ransomware Project (Go)

**Innocent** is an experimental ransomware project written in Go, designed for **educational and research purposes only**.  
It demonstrates the core concepts behind ransomware behavior, including file encryption, key management, and selective targeting.

> ⚠️ **This tool is NOT intended for deployment on any live system outside of controlled, legal environments.**

---

## 🚧 Purpose

This project aims to:

- Help developers and security researchers understand how ransomware operates internally.
- Provide a working example of hybrid encryption (RSA + AES) in Golang.
- Encourage ethical security development and improve defensive strategies.

---

## 🔐 Features

- Generate RSA key pairs
- Encrypt and decrypt files (with AES, RSA-encrypted key)
- Decrypt encrypted private key file
- Supports file extension filters and hidden file skipping

---

## 📁 Components

- `generate-keys`: Create RSA key pairs (private/public).
- `decrypt-key`: Decrypt a previously encrypted private RSA key for use in decryption operations.
- `encrypt`: Encrypt files in a target directory.
- `decrypt`: Decrypt files using a valid private key.

---

## 🚀 Installation

### Prerequisites

- Go 1.18+ installed: [https://golang.org/dl/](https://golang.org/dl/)
- Git (optional, for cloning repository)

### Build from source

```bash
# Clone repository
git clone https://github.com/smile10/innocent.git
cd innocent

# Build executable for your current OS/Arch
go build -o innocent main.go
````

Alternatively, use the included Makefile to build for multiple platforms and architectures:

```bash
make build-linux-amd64         # Build Linux amd64 binary
make build-windows-amd64.exe   # Build Windows amd64 binary
make build-linux-arm64         # Build Linux arm64 binary
# Add other targets as needed
```

The compiled binaries will be saved in the `bin/` directory.

---

## 💻 Usage

Run the `innocent` binary with one of the available commands:

### Generate RSA key pair

```bash
./innocent generate-keys --path ./keys --keysize 4096
```

* `--path`: Directory to save the keys
* `--keysize`: RSA key size in bits (e.g., 2048, 4096)

---

### Decrypt encrypted private key

```bash
./innocent decrypt-key --privatekey ./keys/private.pem --encryptedkey ./keys/private.pem.enc
```

* `--privatekey`: Path to the private key used to decrypt the encrypted private key file
* `--encryptedkey`: Path to the encrypted private key file (e.g. private.pem.enc)

---

### Encrypt files

```bash
./innocent encrypt --publickey ./keys/public.pem --path ./target --encsuffix .locked --ext-blacklist .exe,.dll --skip-hidden
```

* `--publickey`: Path to RSA public key
* `--path`: Target directory for encryption
* `--encsuffix`: Suffix appended to encrypted files
* `--ext-blacklist`: Comma-separated list of file extensions to exclude
* `--ext-whitelist`: Only encrypt files with these extensions (takes priority)
* `--skip-hidden`: Skip hidden files/directories (default: true)

---

### Decrypt files

```bash
./innocent decrypt --privatekey ./keys/private.pem --path ./target --encsuffix .locked --skip-hidden
```

* `--privatekey`: Path to RSA private key
* `--path`: Target directory for decryption
* `--encsuffix`: Suffix of encrypted files to process
* `--ext-blacklist`: Comma-separated list of file extensions to exclude
* `--ext-whitelist`: Only decrypt files with these extensions (takes priority)
* `--skip-hidden`: Skip hidden files/directories (default: true)

---

## ⚠️ Disclaimer

> This project is provided for **educational and ethical research** only.
> You are **fully responsible** for how you use this code.
> The author **does not condone** or support the use of this tool for malicious purposes, including but not limited to:

* Gaining unauthorized access to computer systems.
* Encrypting user data without consent.
* Demanding ransom payments or extortion.

**Any illegal use of this tool is strictly prohibited** and may violate local, national, or international laws.
The author will **not be held liable** for any damage or legal consequences resulting from the misuse of this code.

---

## 🧪 Recommended Usage

Use this project only in the following contexts:

* Personal, offline test environments (e.g., virtual machines, containers).
* Ethical hacking CTF challenges.
* Security training simulations under supervised conditions.

---

## 🛡️ Defending Against Ransomware

Studying ransomware is a powerful way to strengthen defenses. To build safer systems, defenders must think like attackers.

Consider contributing improvements such as:

* Signature-based detection for this ransomware.
* Behavioral monitoring of file encryption patterns.
* Key backup and data recovery automation.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).
