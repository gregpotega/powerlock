import os
import ctypes
import datetime

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

def generate_report(operation, input_path, output_path, algorithm="AES-256-CBC", session_id=None):
    """Generowanie raportu z operacji szyfrowania/deszyfrowania."""
    timestamp = int(datetime.datetime.now().timestamp())
    report_filename = f"powerlock_raport_{operation.lower()}_{timestamp}.txt"
    report_path = os.path.join(output_path, report_filename)
    
    report_content = (
        f"Date and Time: {datetime.datetime.now()}\n"
        f"Operation: {operation}\n"
        f"Input File/Directory: {input_path}\n"
        f"Output File/Directory: {output_path}\n"
        f"Algorithm: {algorithm}\n"
    )
    
    if session_id:
        report_content += f"Session ID: {session_id}\n"
    
    report_content += "----------------------------------------\n"
    
    with open(report_path, "a") as report_file:
        report_file.write(report_content)