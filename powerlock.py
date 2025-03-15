#!/usr/bin/env python3

import os
import sys
import getpass
import hmac
import hashlib
import ctypes
import keyring
import re
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils.help import print_help, print_info

# Encryption Configuration
SALT_SIZE =16
KEY_SIZE = 32
IV_SIZE = 16
ITERATIONS = 100_000
HMAC_KEY_SIZE = 32 



def derive_key(password: str, salt: bytes) -> bytes:
    # Generates a key based on a password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + HMAC_KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    key_material = kdf.derive(password.encode())
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]

def set_readonly(file_path: str):
    # Sets the file to read-only.
    if os.name == 'nt':
        FILE_ATTRIBUTE_READONLY = 0x01
        ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_READONLY)
    else:
        os.chmod(file_path, 0o400)

def remove_readonly(file_path: str):
    # Removes the readonly attribute from a file.
    if os.name == 'nt':
        FILE_ATTRIBUTE_NORMAL = 0x80
        ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL)
    else:
        os.chmod(file_path, 0o600)

def encrypt_file(input_file: str, output_file: str, password: str):
    try:
        if not os.path.exists(input_file):
            print(f"Error: File {input_file} does not exist.")
            return
        
        salt = os.urandom(SALT_SIZE)
        iv = os.urandom(IV_SIZE)
        key, hmac_key = derive_key(password, salt)

        with open(input_file, 'rb') as f:
            plaintext = f.read()
        
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len]) * pad_len
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        hmac_digest = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        
        with open(output_file, 'wb') as f:
            f.write(salt + iv + hmac_digest + ciphertext)
        
        set_readonly(output_file)
        print(f"Encrypted file: {output_file}")
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file(input_file: str, output_file: str, password: str):
    try:
        if not os.path.exists(input_file):
            print(f"Error: File {input_file} does not exist")
            return
        
        remove_readonly(input_file)
        
        with open(input_file, 'rb') as f:
            data = f.read()
        
        salt, iv, hmac_stored, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+IV_SIZE], data[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+32], data[SALT_SIZE+IV_SIZE+32:]
        key, hmac_key = derive_key(password, salt)
        
        hmac_calculated = hmac.new(hmac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(hmac_stored, hmac_calculated):
            print("Error: File has been modified or password is incorrect!")
            return
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]
        
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        
        print(f"Decrypted file: {output_file}")
    except Exception as e:
        print(f"Error during decryption: {e}")

def encrypt_directory(input_dir: str, output_dir: str, password: str):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for root, _, files in os.walk(input_dir):
            rel_path = os.path.relpath(root, input_dir)
            target_root = os.path.join(output_dir, rel_path)
            if not os.path.exists(target_root):
                os.makedirs(target_root)
            
            for file in files:
                encrypt_file(os.path.join(root, file), os.path.join(target_root, file + '.enc'), password)
    except Exception as e:
        print(f"Error during directory encryption: {e}")

def decrypt_directory(input_dir: str, output_dir: str, password: str):
    try:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        for root, _, files in os.walk(input_dir):
            rel_path = os.path.relpath(root, input_dir)
            target_root = os.path.join(output_dir, rel_path)
            if not os.path.exists(target_root):
                os.makedirs(target_root)
            
            for file in files:
                if file.endswith('.enc'):
                    decrypt_file(os.path.join(root, file), os.path.join(target_root, file[:-4]), password)
    except Exception as e:
        print(f"Error during directory decryption: {e}")

def get_password(service_name: str, username: str) -> str:
    """
    Retrieves the password from the system keyring.
    
    Args:
        service_name (str): The name of the service.
        username (str): The username for which to retrieve the password.
    
    Returns:
        str: The retrieved password.
    """
    return keyring.get_password(service_name, username)

def set_password(service_name: str, username: str, password: str):
    """
    Sets the password in the system keyring.
    
    Args:
        service_name (str): The name of the service.
        username (str): The username for which to set the password.
        password (str): The password to set.
    """
    keyring.set_password(service_name, username, password)

def validate_password_strength(password: str) -> bool:
    """
    Validates the strength of a password.
    
    Args:
        password (str): The password to validate.
    
    Returns:
        bool: True if the password is strong, False otherwise.
    """
    if len(password) < 8:
        print("Password must be at least 8 characters long.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Password must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", password):
        print("Password must contain at least one lowercase letter.")
        return False
    if not re.search(r"\d", password):
        print("Password must contain at least one digit.")
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("Password must contain at least one special character.")
        return False
    return True

def main():
    try:
        if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
            print_help()
            sys.exit(0)
        
        if sys.argv[1] in ("-i", "--info"):
            print_info()
            sys.exit(0)

        if len(sys.argv) < 4:
            print("Use: powerlock (-e | -d) or (--encrypt | --decrypt) <input_path> <output_path>")
            sys.exit(1)
        
        mode = sys.argv[1]
        input_path = sys.argv[2]
        output_path = sys.argv[3]
        
        if not os.path.exists(input_path):
            print(f"Error: {input_path} does not exist.")
            sys.exit(1)
        
        service_name = "powerlock"
        username = getpass.getuser()
        password = get_password(service_name, username)
        
        if not password:
            password = getpass.getpass("Enter your password: ")
            if not validate_password_strength(password):
                sys.exit(1)
            set_password(service_name, username, password)
        
        if mode in ("--encrypt", "-e"):
            if os.path.isdir(input_path):
                encrypt_directory(input_path, output_path, password)
            else:
                encrypt_file(input_path, output_path, password)
        elif mode in ("--decrypt", "-d"):
            if os.path.isdir(input_path):
                decrypt_directory(input_path, output_path, password)
            else:
                decrypt_file(input_path, output_path, password)
        else:
            print("Unknown option!")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
