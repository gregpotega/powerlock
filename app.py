import os
import sys
import json
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Konfiguracja szyfrowania
SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
ITERATIONS = 100_000


def derive_key(password: str, salt: bytes) -> bytes:
    """Generuje klucz na podstawie hasła i soli."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_file: str, output_file: str, password: str):
    """Szyfruje plik AES-256 w trybie CBC."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Padding
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    print(f"Plik zaszyfrowany: {output_file}")


def decrypt_file(input_file: str, output_file: str, password: str):
    """Deszyfruje plik AES-256 w trybie CBC."""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    salt, iv, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+IV_SIZE], data[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Usunięcie paddingu
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    print(f"Plik odszyfrowany: {output_file}")


def encrypt_directory(input_dir: str, output_dir: str, password: str):
    """Szyfruje wszystkie pliki w katalogu."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for root, _, files in os.walk(input_dir):
        rel_path = os.path.relpath(root, input_dir)
        target_root = os.path.join(output_dir, rel_path)
        if not os.path.exists(target_root):
            os.makedirs(target_root)
        
        for file in files:
            encrypt_file(os.path.join(root, file), os.path.join(target_root, file + '.enc'), password)

def decrypt_directory(input_dir: str, output_dir: str, password: str):
    """Deszyfruje wszystkie pliki w katalogu."""
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


def main():
    if len(sys.argv) < 4:
        print("Użycie: python script.py (encrypt|decrypt) <input_file|input_dir> <output_file|output_dir>")
        sys.exit(1)
    
    mode = sys.argv[1]
    input_path = sys.argv[2]
    output_path = sys.argv[3]
    password = getpass.getpass("Podaj hasło: ")
    
    if mode == "encrypt":
        if os.path.isdir(input_path):
            encrypt_directory(input_path, output_path, password)
        else:
            encrypt_file(input_path, output_path, password)
    elif mode == "decrypt":
        if os.path.isdir(input_path):
            decrypt_directory(input_path, output_path, password)
        else:
            decrypt_file(input_path, output_path, password)
    else:
        print("Nieznana opcja!")
        sys.exit(1)

if __name__ == "__main__":
    main()
