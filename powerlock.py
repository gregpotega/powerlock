#!/usr/bin/env python3

import os
import sys
import getpass
import logging
from utils.help import print_help, print_info
from utils.password_utils import get_password_with_confirmation, get_password_without_confirmation, set_password
from utils.encryption import encrypt_file, decrypt_file, encrypt_directory, decrypt_directory

# Configure logging
logging.basicConfig(filename='powerlock.log', level=logging.ERROR)

def main():
    try:
        if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
            print_help()
            sys.exit(0)
        
        if sys.argv[1] in ("-i", "--info"):
            print_info()
            sys.exit(0)

        if len(sys.argv) < 4:
            print("Use: powerlock (-e | -d | -et | -dt) or (--encrypt | --decrypt | --encrypt-title | --decrypt-title) <input_path> <output_path>")
            sys.exit(1)
        
        mode = sys.argv[1]
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        
        if not os.path.exists(input_path):
            print(f"Error: {input_path} does not exist.")
            sys.exit(1)
        
        service_name = "powerlock"
        username = getpass.getuser()
        
        if mode in ("--encrypt", "-e"):
            password = get_password_with_confirmation()
            set_password(service_name, username, password)
            if os.path.isdir(input_path):
                encrypt_directory(input_path, output_path, password)
            else:
                encrypt_file(input_path, output_path, password)
        elif mode in ("--decrypt", "-d"):
            password = get_password_without_confirmation()
            if os.path.isdir(input_path):
                decrypt_directory(input_path, output_path, password)
            else:
                decrypt_file(input_path, output_path, password)
        elif mode in ("--encrypt-title", "-et"):
            password = get_password_with_confirmation()
            set_password(service_name, username, password)
            if os.path.isdir(input_path):
                encrypt_directory(input_path, output_path, password, encrypt_title=True)
            else:
                encrypt_file(input_path, output_path, password, encrypt_title=True)
        elif mode in ("--decrypt-title", "-dt"):
            password = get_password_without_confirmation()
            if os.path.isdir(input_path):
                decrypt_directory(input_path, output_path, password, decrypt_title=True)
            else:
                decrypt_file(input_path, output_path, password, decrypt_title=True)
        else:
            print("Unknown option!")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nProcess interrupted by user. Exiting.")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"File not found error: {e}")
        print(f"File not found error: {e}")
        sys.exit(1)
    except PermissionError as e:
        logging.error(f"Permission error: {e}")
        print(f"Permission error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
