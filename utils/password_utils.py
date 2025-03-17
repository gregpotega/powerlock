import re
import sys
import getpass
import keyring

def validate_password_strength(password: str) -> bool:
    """
    Validates the strength of a password.
    
    Args:
        password (str): The password to validate.
    
    Returns:
        bool: True if the password is strong, False otherwise.
    """
    if len(password) < 6:
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

def get_password_with_confirmation() -> str:
    """
    Prompts the user to enter and confirm their password.
    
    Returns:
        str: The confirmed password.
    """
    attempts = 0
    max_attempts = 3
    while attempts < max_attempts:
        password = getpass.getpass("Enter your password: ")
        if not validate_password_strength(password):
            print("Invalid password. Please try again.\n-------------")
            attempts += 1
            continue
        confirm_password = getpass.getpass("Confirm your password: ")
        if password == confirm_password:
            return password
        else:
            print("Passwords do not match. Please try again.\n-------------")
            attempts += 1
    print("Maximum password attempts exceeded. Exiting.")
    sys.exit(1)

def get_password_without_confirmation() -> str:
    """
    Prompts the user to enter their password without confirmation.
    
    Returns:
        str: The entered password.
    """
    attempts = 0
    max_attempts = 3
    while attempts < max_attempts:
        password = getpass.getpass("Enter your password: ")
        if validate_password_strength(password):
            return password
        else:
            print("Invalid password. Please try again.\n-------------")
            attempts += 1
    print("Maximum password attempts exceeded. Exiting.")
    sys.exit(1)

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