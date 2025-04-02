def print_help():
    help_text = """

Use: powerlock (-e | -d) or (--encrypt | --decrypt) <input_path> <output_path>

Options:
  -e,   --encrypt       Encrypts a file or directory
  -et,  --encrypt-title Encrypts a file or directory with a title
  -d,   --decrypt       Decrypts a file or directory
  -h,   --help          Displays this help
  -i,   --info          Information about the program

Examples:

    Encryption:

        File:               powerlock -e file.txt file.txt.enc (recommended)
        Directory:          powerlock -e catalog catalog.enc (recommended)
        File on the fly:    powerlock -e file.txt file.txt
        File with title:    powerlock -et file.txt file.txt.enc

    Decryption:

        File:               powerlock -d file.txt.enc file.txt (recommended)
        Directory:          powerlock -d catalog.enc catalog (recommended)
        File on the fly:    powerlock -d file.txt file.txt
        File with title:    powerlock -d P4iqiAi== file.txt 

"""
    print(help_text)

def print_info():
    info_text = f"""
-------------------------------------------
Program Name:   {NAME_APP}
Version:        {PROGRAM_VERSION}
Author:         {AUTHOR}
Licence:        {LICENSE}
Description:    {DESCRIPTION}
-------------------------------------------
This program is licensed under the Apache License 2.0.
-------------------------------------------
"""
    print(info_text)

def print_info_gui():
    info_text = f"""
Name: {NAME_APP}
Version: {PROGRAM_VERSION}
Author: {AUTHOR}
Licence: {LICENSE}  
"""
    return info_text

NAME_APP = "PowerLock"
PROGRAM_VERSION = "2.0.1"
AUTHOR = "Greg Potega"
LICENSE = "Apache 2.0"
DESCRIPTION = "PowerLock - a tool for encrypting and decrypting files and directories."