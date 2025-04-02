#!/usr/bin/env python3
import os
import sys
import tkinter as tk
from tkinter import filedialog, ttk
from utils.encryption import encrypt_file, decrypt_file, encrypt_directory, decrypt_directory, derive_key, decrypt_filename
from utils.password_utils import validate_password_strength
from utils.file_utils import generate_report
from utils.help import print_info_gui, PROGRAM_VERSION
import uuid

def select_input():
    input_type = input_type_var.get()
    if input_type == "File":
        path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])

    else:
        path = filedialog.askdirectory()
    input_path_entry.delete(0, tk.END)
    input_path_entry.insert(0, path)

def select_output():
    path = filedialog.askdirectory()
    output_path_entry.delete(0, tk.END)
    output_path_entry.insert(0, path)

def toggle_confirm_password(*args):
    if operation_var.get() == "Encrypt":
        confirm_password_label.grid()
        confirm_password_entry.grid()
        skip_validation_checkbutton.grid()
    else:
        confirm_password_label.grid_remove()
        confirm_password_entry.grid_remove()
        skip_validation_checkbutton.grid_remove()
    skip_validation_var.set(False)
    encrypt_title_var.set(False)
    update_encrypt_title_text()

def update_encrypt_title_text(*args):
    if operation_var.get() == "Encrypt":
        encrypt_title_checkbutton.config(text="Encrypt file titles")
    else:
        encrypt_title_checkbutton.config(text="Decrypt file titles")

def process():
    input_path = os.path.normpath(input_path_entry.get())
    output_path = os.path.normpath(output_path_entry.get())
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    operation = operation_var.get()
    skip_validation = skip_validation_var.get()
    encrypt_title = encrypt_title_var.get()
    generate_report_flag = generate_report_var.get()

    if not input_path or not output_path or not password:
        custom_messagebox("Error", "All fields are required!")
        return

    if operation == "Encrypt":
        if password != confirm_password:
            custom_messagebox("Error", "Passwords do not match!")
            return
        if not skip_validation and not validate_password_strength(password):
            custom_messagebox("Error", "Password is too weak!")
            return

    session_id = str(uuid.uuid4())

    try:
        if operation == "Encrypt":
            if os.path.isdir(input_path):
                encrypt_directory(input_path, output_path, password, encrypt_title=encrypt_title)
            else:
                file_name = os.path.basename(input_path)
                output_file_path = os.path.normpath(os.path.join(output_path, file_name + ('.enc' if not encrypt_title else '')))
                encrypt_file(input_path, output_file_path, password, encrypt_title=encrypt_title)
            custom_messagebox("Success", "Encryption completed successfully!")
            if generate_report_flag:
                generate_report("Encrypt", input_path, output_path, session_id=session_id)
        else:
            if os.path.isdir(input_path):
                decrypt_directory(input_path, output_path, password, decrypt_title=encrypt_title)
            else:
                file_name = os.path.basename(input_path)
                if encrypt_title:
                    with open(input_path, 'rb') as f:
                        salt = f.read(16)
                    key, _ = derive_key(password, salt)
                    try:
                        file_name = decrypt_filename(file_name, key)
                    except Exception as e:
                        custom_messagebox("Error", f"Failed to decrypt file title: {e}")
                        return
                else:
                    if file_name.endswith('.enc'):
                        file_name = file_name[:-4]
                output_file_path = os.path.join(output_path, file_name)
                decrypt_file(input_path, output_file_path, password, decrypt_title=encrypt_title)
            custom_messagebox("Success", "Decryption completed successfully!")
            if generate_report_flag:
                generate_report("Decrypt", input_path, output_path, session_id=session_id)
    except ValueError:
        custom_messagebox("Error", "Incorrect password!")
    except Exception as e:
        custom_messagebox("Error", str(e))
    finally:
        skip_validation_var.set(False)
        encrypt_title_var.set(False)
        generate_report_var.set(False)
        password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)

def show_about():
    info = print_info_gui()
    custom_messagebox("About", info)

def custom_messagebox(title, message):
    """Creates a custom dialog window that opens in the center of the main application window."""
    dialog = tk.Toplevel(root)  # Create a new top-level window
    dialog.title(title)  # Set the title of the dialog window
    dialog.resizable(False, False)  # Disable resizing of the dialog window

    # Get the size and position of the main application window
    root_x = root.winfo_x()  # X-coordinate of the main window
    root_y = root.winfo_y()  # Y-coordinate of the main window
    root_width = root.winfo_width()  # Width of the main window
    root_height = root.winfo_height()  # Height of the main window

    # Set the size of the dialog window
    dialog_width = 300
    dialog_height = 150

    # Calculate the position to center the dialog on the main window
    x = root_x + (root_width // 2) - (dialog_width // 2)
    y = root_y + (root_height // 2) - (dialog_height // 2)

    # Set the size and position of the dialog window
    dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
    dialog.transient(root)  # Make the dialog a child of the main window
    dialog.grab_set()  # Block interaction with the main window until the dialog is closed

    # Add a label to display the message
    label = ttk.Label(dialog, text=message, wraplength=280, anchor="center", justify="center")
    label.pack(pady=20, padx=10)

    # Add a button to close the dialog
    button = ttk.Button(dialog, text="OK", command=dialog.destroy)
    button.pack(pady=10)

    # Pause the main window until the dialog is closed
    root.wait_window(dialog)

root = tk.Tk()
root.title(f"PowerLock {PROGRAM_VERSION}  - File Encryption")
root.geometry("430x580")
root.resizable(False, False)

operation_frame = ttk.LabelFrame(root, text="Operation Settings", padding=(10, 10))
operation_frame.pack(pady=10, padx=10, fill="x")

ttk.Label(operation_frame, text="Operation:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
operation_var = tk.StringVar(value="Encrypt")
operation_menu = ttk.Combobox(operation_frame, textvariable=operation_var, values=["Encrypt", "Decrypt"], state="readonly", width=15)
operation_menu.grid(row=0, column=1, padx=5, pady=5, sticky="w")

ttk.Label(operation_frame, text="Input Type:").grid(row=0, column=2, padx=5, pady=5, sticky="w")
input_type_var = tk.StringVar(value="File")
input_type_menu = ttk.Combobox(operation_frame, textvariable=input_type_var, values=["File", "Directory"], state="readonly", width=15)
input_type_menu.grid(row=0, column=3, padx=5, pady=5, sticky="w")

path_frame = ttk.LabelFrame(root, text="File Paths", padding=(10, 10))
path_frame.pack(pady=10, padx=10, fill="x")

ttk.Label(path_frame, text="Input Path:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
input_path_entry = ttk.Entry(path_frame, width=35)
input_path_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
ttk.Button(path_frame, text="Set", command=select_input, width=8).grid(row=0, column=2, padx=5, pady=5)

ttk.Label(path_frame, text="Output Path:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
output_path_entry = ttk.Entry(path_frame, width=35)
output_path_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
ttk.Button(path_frame, text="Set", command=select_output, width=8).grid(row=1, column=2, padx=5, pady=5)

password_frame = ttk.LabelFrame(root, text="Password Settings", padding=(10, 10))
password_frame.pack(pady=10, padx=10, fill="x")

ttk.Label(password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
password_entry = ttk.Entry(password_frame, show="*", width=30)
password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")

confirm_password_label = ttk.Label(password_frame, text="Confirm Password:")
confirm_password_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
confirm_password_entry = ttk.Entry(password_frame, show="*", width=30)
confirm_password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")

skip_validation_var = tk.BooleanVar()
skip_validation_checkbutton = ttk.Checkbutton(password_frame, text="Use a simple password", variable=skip_validation_var)
skip_validation_checkbutton.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="w")

options_frame = ttk.LabelFrame(root, text="Additional Options", padding=(10, 10))
options_frame.pack(pady=10, padx=10, fill="x")

encrypt_title_var = tk.BooleanVar()
encrypt_title_checkbutton = ttk.Checkbutton(options_frame, text="Encrypt file titles", variable=encrypt_title_var)
encrypt_title_checkbutton.grid(row=0, column=0, padx=5, pady=5, sticky="w")

generate_report_var = tk.BooleanVar()
generate_report_checkbutton = ttk.Checkbutton(options_frame, text="Generate report", variable=generate_report_var)
generate_report_checkbutton.grid(row=1, column=0, padx=5, pady=5, sticky="w")

button_frame = ttk.Frame(root, padding=(10, 10))
button_frame.pack(pady=10, padx=10, fill="x")

process_button = ttk.Button(button_frame, text="Process", command=process, width=25)
process_button.pack(side="left", padx=5, pady=5)

about_button = ttk.Button(button_frame, text="About", command=show_about, width=15)
about_button.pack(side="right", padx=5, pady=5)

operation_var.trace_add("write", toggle_confirm_password)
operation_var.set("Encrypt")
toggle_confirm_password()
update_encrypt_title_text()

root.mainloop()