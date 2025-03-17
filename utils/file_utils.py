import os
import ctypes

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