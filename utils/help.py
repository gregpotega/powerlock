def print_help():
    help_text = """

Use: powerlock (-e | -d) or (--encrypt | --decrypt) <input_path> <output_path>

Options:
  -e, --encrypt     Encrypts a file or directory
  -d, --decrypt     Decrypts a file or directory
  -h, --help        Displays this help
  -i, --info        Information about the program

Examples:

    Encryption:

        File:               powerlock -e file.txt file.txt.enc (recommended)
        Directory:          powerlock -e catalog catalog.enc (recommended)
        File on the fly:    powerlock -e file.txt file.txt

    Decryption:

        File:               powerlock -d file.txt.enc file.txt (recommended)
        Directory:          powerlock -d catalog.enc catalog (recommended)
        File on the fly:    powerlock -d file.txt file.txt   

"""
    print(help_text)

def print_info():
    info_text = """
-------------------------------------------
Program Name:   PowerLock
Version:        1.0.0
Author:         Greg Potega
Licence:        Apache 2.0
Description:    PowerLock - a tool for encrypting and decrypting files and directories.
-------------------------------------------   
"""
    print(info_text)