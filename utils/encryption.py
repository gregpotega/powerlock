import os
import hmac
import hashlib
import tempfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utils.file_utils import set_readonly, remove_readonly

# Encryption Configuration
SALT_SIZE = 16
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
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(salt + iv + hmac_digest + ciphertext)
            temp_file_path = temp_file.name
        
        os.rename(temp_file_path, output_file)
        set_readonly(output_file)
        print(f"Encrypted file: {output_file}")
    except Exception as e:
        print(f"Error during encryption: {e}")
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

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
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(plaintext)
            temp_file_path = temp_file.name
        
        os.rename(temp_file_path, output_file)
        print(f"Decrypted file: {output_file}")
    except Exception as e:
        print(f"Error during decryption: {e}")
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

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