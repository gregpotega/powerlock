import unittest
import keyring
import os
import shutil
from powerlock import derive_key, set_readonly, remove_readonly, encrypt_file, decrypt_file, encrypt_directory, decrypt_directory, derive_key, get_password, set_password


class TestPowerlock(unittest.TestCase):
    def test_derive_key(self):
        password = "fg45454564"
        salt = b"testsalt"
        key, hmac_key = derive_key(password, salt)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(hmac_key), 32)

    def setUp(self):
        # Create a temporary directory for testing
        self.test_dir = "test_dir"
        self.test_file = os.path.join(self.test_dir, "test_file.txt")
        self.encrypted_file = self.test_file + ".enc"
        self.decrypted_file = os.path.join(self.test_dir, "decrypted_file.txt")
        os.makedirs(self.test_dir, exist_ok=True)
        with open(self.test_file, "w") as f:
            f.write("This is a test file.")

    def tearDown(self):
        # Remove the temporary directory after testing
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_set_readonly(self):
        set_readonly(self.test_file)
        self.assertFalse(os.access(self.test_file, os.W_OK))

    def test_remove_readonly(self):
        set_readonly(self.test_file)
        remove_readonly(self.test_file)
        self.assertTrue(os.access(self.test_file, os.W_OK))

    def test_encrypt_file(self):
        password = "testpassword"
        encrypt_file(self.test_file, self.encrypted_file, password)
        self.assertTrue(os.path.exists(self.encrypted_file))

    def test_decrypt_file(self):
        password = "testpassword"
        encrypt_file(self.test_file, self.encrypted_file, password)
        decrypt_file(self.encrypted_file, self.decrypted_file, password)
        self.assertTrue(os.path.exists(self.decrypted_file))
        with open(self.decrypted_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test file.")

    def test_encrypt_directory(self):
        password = "testpassword"
        output_dir = self.test_dir + "_enc"
        encrypt_directory(self.test_dir, output_dir, password)
        self.assertTrue(os.path.exists(output_dir))
        self.assertTrue(os.path.exists(os.path.join(output_dir, "test_file.txt.enc")))

    def test_decrypt_directory(self):
        password = "testpassword"
        output_dir = self.test_dir + "_enc"
        decrypt_dir = self.test_dir + "_dec"
        encrypt_directory(self.test_dir, output_dir, password)
        decrypt_directory(output_dir, decrypt_dir, password)
        self.assertTrue(os.path.exists(decrypt_dir))
        self.assertTrue(os.path.exists(os.path.join(decrypt_dir, "test_file.txt")))
        with open(os.path.join(decrypt_dir, "test_file.txt"), "r") as f:
            content = f.read()
        self.assertEqual(content, "This is a test file.")

    def test_set_password(self):
        service_name = "test_service"
        username = "test_user"
        password = "test_password"
        
        # Set the password
        set_password(service_name, username, password)
        
        # Retrieve the password to verify it was set correctly
        retrieved_password = keyring.get_password(service_name, username)
        self.assertEqual(retrieved_password, password)

    def test_get_password(self):
        service_name = "test_service"
        username = "test_user"
        password = "test_password"
        
        # Set the password first
        keyring.set_password(service_name, username, password)
        
        # Retrieve the password using the function
        retrieved_password = get_password(service_name, username)
        self.assertEqual(retrieved_password, password)

if __name__ == "__main__":
    unittest.main()