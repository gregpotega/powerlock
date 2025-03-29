import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from utils.encryption import encrypt_file, decrypt_file, encrypt_directory, decrypt_directory, derive_key, decrypt_filename
from utils.password_utils import validate_password_strength
from utils.file_utils import generate_report  
import uuid  

# Allows the user to select an input file or directory based on the selected input type.
def select_input():
    input_type = input_type_var.get()
    if input_type == "File":
        path = filedialog.askopenfilename()
    else:
        path = filedialog.askdirectory()
    input_path_entry.delete(0, tk.END)
    input_path_entry.insert(0, path)
 
# Allows the user to select an output directory.
def select_output():
    input_type = input_type_var.get()
    if input_type == "File":
        path = filedialog.askdirectory()
    else:
        path = filedialog.askdirectory()
    output_path_entry.delete(0, tk.END)
    output_path_entry.insert(0, path)

# Manages the visibility of password confirmation fields and options based on the selected operation.
def toggle_confirm_password(*args):
    """Zarządzanie widocznością pól w zależności od wybranej operacji."""
    if operation_var.get() == "Encrypt":
        confirm_password_label.pack_forget()
        confirm_password_entry.pack_forget()
        skip_validation_checkbutton.pack_forget()
        
        confirm_password_label.pack(pady=5, before=encrypt_title_checkbutton)
        confirm_password_entry.pack(pady=5, before=encrypt_title_checkbutton)
        skip_validation_checkbutton.pack(pady=5, before=encrypt_title_checkbutton)
    else:
        confirm_password_label.pack_forget()
        confirm_password_entry.pack_forget()
        skip_validation_checkbutton.pack_forget()

    # Resetting checkboxes when changing operations
    skip_validation_var.set(False)
    encrypt_title_var.set(False)
    

    update_encrypt_title_text()

# Updated file title encryption checkbox text.
def update_encrypt_title_text(*args):
    if operation_var.get() == "Encrypt":
        encrypt_title_checkbutton.config(text="Encrypt file titles")
    else:
        encrypt_title_checkbutton.config(text="Decrypt file titles")

# Handles the encryption/decryption process.
def process():
    input_path = input_path_entry.get()
    output_path = output_path_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()
    operation = operation_var.get()
    skip_validation = skip_validation_var.get()
    encrypt_title = encrypt_title_var.get()
    generate_report_flag = generate_report_var.get()
    
    if not input_path or not output_path or not password:
        messagebox.showerror("Error", "All fields are required!")
        return
    
    if operation == "Encrypt":
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        if not skip_validation and not validate_password_strength(password):
            messagebox.showerror("Error", "Password is too weak!")
            return
    
    session_id = str(uuid.uuid4())  # Generating a unique session ID
    
    try:
        if operation == "Encrypt":
            if os.path.isdir(input_path):
                encrypt_directory(input_path, output_path, password, encrypt_title=encrypt_title)
            else:
                file_name = os.path.basename(input_path)
                if encrypt_title:
                    output_file_path = os.path.join(output_path, file_name)
                else:
                    output_file_path = os.path.join(output_path, file_name + '.enc')
                encrypt_file(input_path, output_file_path, password, encrypt_title=encrypt_title)
            messagebox.showinfo("Success", "Encryption completed successfully!")
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
                        messagebox.showerror("Error", f"Failed to decrypt file title: {e}")
                        return
                else:
                    if file_name.endswith('.enc'):
                        file_name = file_name[:-4]
                output_file_path = os.path.join(output_path, file_name)
                decrypt_file(input_path, output_file_path, password, decrypt_title=encrypt_title)
            messagebox.showinfo("Success", "Decryption completed successfully!")
            if generate_report_flag:
                generate_report("Decrypt", input_path, output_path, session_id=session_id)
    except ValueError as e:
        messagebox.showerror("Error", "Incorrect password!")
    except Exception as e:
        messagebox.showerror("Error", str(e))
    finally:
        skip_validation_var.set(False)
        encrypt_title_var.set(False)
        password_entry.delete(0, tk.END)
        confirm_password_entry.delete(0, tk.END)

def show_about():
    messagebox.showinfo("About", "PowerLock v2.0\nAuthor: Greg Potega\nLicense: Apache 2.0")


root = tk.Tk()
root.title("PowerLock - File Encryption")
root.geometry("500x650")  
root.resizable(False, False)

frame = tk.Frame(root)
frame.pack(pady=5)

# Operation (Encrypt/Decrypt)
tk.Label(frame, text="Operation:").grid(row=0, column=0, padx=5)
operation_var = tk.StringVar(value="Encrypt")  # Set to Encrypt by default
operation_menu = ttk.Combobox(frame, textvariable=operation_var, values=["Encrypt", "Decrypt"], state="readonly", width=10)
operation_menu.grid(row=0, column=1, padx=5)
operation_var.trace("w", toggle_confirm_password)  # Tracking changes to operations
operation_var.trace("w", update_encrypt_title_text)  # Tracking changes to operations

# Input Type (File/Directory)
tk.Label(frame, text="Input Type:").grid(row=0, column=2, padx=5)
input_type_var = tk.StringVar(value="File")
input_type_menu = ttk.Combobox(frame, textvariable=input_type_var, values=["File", "Directory"], state="readonly", width=10)
input_type_menu.grid(row=0, column=3, padx=5)

# Entrance Path
tk.Label(root, text="Input Path:").pack(pady=5)
input_path_entry = tk.Entry(root, width=50)
input_path_entry.pack(pady=5)
tk.Button(root, text="Select Input", command=select_input).pack(pady=5)

# Output path
tk.Label(root, text="Output Path:").pack(pady=5)
output_path_entry = tk.Entry(root, width=50)
output_path_entry.pack(pady=5)
tk.Button(root, text="Select Output", command=select_output).pack(pady=5)

# Password
tk.Label(root, text="Password:").pack(pady=5)
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(pady=5)

# Confirm password
confirm_password_label = tk.Label(root, text="Confirm Password:")
confirm_password_entry = tk.Entry(root, show="*", width=40)

# Option to skip password validation
skip_validation_var = tk.BooleanVar()
skip_validation_checkbutton = tk.Checkbutton(root, text="Use a simple password (not recommended).", variable=skip_validation_var)

# File Title Encryption Option
encrypt_title_var = tk.BooleanVar()
encrypt_title_checkbutton = tk.Checkbutton(root, text="Encrypt file titles", variable=encrypt_title_var)

# Report generation option
generate_report_var = tk.BooleanVar()
generate_report_checkbutton = tk.Checkbutton(root, text="Generate report", variable=generate_report_var)

# Buttons
process_button = tk.Button(root, text="Process", command=process, font=("Helvetica", 14, "bold"), bg="green", fg="white", width=20, height=2)
process_button.pack(side=tk.BOTTOM, pady=5)
tk.Button(root, text="About", command=show_about).pack(side=tk.BOTTOM, pady=5)

# Place checkboxes in front of buttons
generate_report_checkbutton.pack(pady=5, before=process_button)
encrypt_title_checkbutton.pack(pady=5, before=generate_report_checkbutton)

# Setting the default operation and calling the visibility management function
operation_var.set("Encrypt")
toggle_confirm_password()
update_encrypt_title_text()

# Starting the main application loopi
root.mainloop()

