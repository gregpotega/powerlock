# PowerLock

PowerLock is a tool for encrypting and decrypting files and directories using the AES-256 algorithm in CBC mode with additional HMAC for data integrity.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Linux](#installation-linux)
  - [Windows](#installation-windows)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Features
- **Secure file and directory encryption** using AES-256-CBC.
- **Key generation** based on user password and salt using PBKDF2-HMAC-SHA256.
- **Data integrity verification** via HMAC-SHA256.
- **File attribute handling** (read-only mode, preventing modifications and deletion).
- **Recursive encryption and decryption of directories**.
- **Unit tests** ensuring correct functionality.

## Requirements
- Python 3.8+
- Libraries: `cryptography`, `unittest`, `os`, `shutil`, `getpass`, `logging`, `hmac`, `hashlib`, `tempfile`, `ctypes`, `re`, `keyring`

## Installation

### Installation Linux
PowerLock is distributed as a .deb package for easy installation, but it must be run from the terminal.

1. Download the PowerLock package for Linux. 
2. Install using:
   ```sh
   sudo dpkg -i powerlock.deb
   ```
3. Verify installation:
   ```sh
   powerlock --help
   ```

### Installation Windows
1. Download the PowerLock executable (powerlock.exe).
2. Move the file to a convenient location (e.g., C:\PowerLock).
3. Open a Command Prompt (Win + R, type cmd, and press Enter).
4. Navigate to the folder where PowerLock is stored:
   ```sh
   cd C:\PowerLock\
   ```
5. Run the program with:
   ```sh
   powerlock --help
   ```

## Usage
Using PowerLock is simple. You can encrypt or decrypt files and directories with a single command.

Encrypt a file:
   ```sh
   powerlock -e file.txt file.txt.enc
   ```
Encrypt a directory:
   ```sh
   powerlock -e folder folder.enc
   ```
Decrypt a file:
   ```sh
   powerlock -d file.txt.enc file.txt
   ```
Decrypt a directory:
   ```sh
   powerlock -d folder.enc folder
   ```

## License
This project is licensed under the Apache 2.0 License. See the [LICENSE](LICENSE) file for details.

## Contact
If you have any questions or need support, please contact [me](mailto:potegagreg@gmail.com).

