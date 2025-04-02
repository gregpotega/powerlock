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
   sudo dpkg -i powerlock_2.0.1.deb
   ```
3. Verify installation:
   ```sh
   powerlock --help
   ```

### Installation Windows
1. Download the PowerLock GUI installer (e.g., `PowerLock_GUI_Setup.exe`) from the official website.
2. Run the installer by double-clicking the downloaded file.
3. Follow the installation wizard to complete the setup.
4. Once installed, you can launch PowerLock GUI from the Start Menu or by searching for "PowerLock" in the Windows search bar.
5. To verify the installation, open the program and ensure the GUI loads correctly.

Alternatively, you can still use the command-line version:
1. Download the PowerLock executable (`powerlock.exe`).
2. Move the file to a convenient location (e.g., `C:\PowerLock`).
3. Open a Command Prompt (Win + R, type `cmd`, and press Enter).
4. Navigate to the folder where PowerLock is stored:
   ```sh
   cd C:\PowerLock\
   ```
5. Run the program with:
   ```sh
   powerlock --help
   ```

## Usage

### Using PowerLock GUI on Linux
PowerLock also provides a graphical user interface (GUI) for easier usage. To launch the GUI, simply run the following command in your terminal:

   ```sh
   powerlock-gui
   ```

This will open the PowerLock GUI, where you can easily select files or directories to encrypt or decrypt, set passwords, and configure additional options.

### Command-Line Usage
Using PowerLock via the command line is simple. You can encrypt or decrypt files and directories with a single command.

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

## Website
🌐 **Official website:** [powerlock.potegait.com](https://powerlock.potegait.com)

