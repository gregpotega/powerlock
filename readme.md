🔐 Jak działa szyfrowanie w Twoim programie?

Twoja aplikacja wykorzystuje algorytm AES-256 w trybie CBC, a klucz szyfrowania jest tworzony dynamicznie przy użyciu hasła użytkownika i soli. Oto krok po kroku, jak to działa:
🏗 1. Generowanie klucza szyfrowania

🔹 Użytkownik podaje hasło (ale nigdy go nie zapisujemy!).
🔹 Tworzymy losową sól (16 bajtów).
🔹 Za pomocą PBKDF2-HMAC-SHA256 generujemy 256-bitowy (32 bajty) klucz szyfrowania.

📌 Kod odpowiedzialny za to:

def derive_key(password: str, salt: bytes) -> bytes:
    """Generuje klucz na podstawie hasła i soli."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,  # 32 bajty (256 bitów)
        salt=salt,
        iterations=ITERATIONS,  # 100 000 iteracji
        backend=default_backend()
    )
    return kdf.derive(password.encode())  # Klucz AES-256

📌 Dlaczego tak?

    PBKDF2 (Password-Based Key Derivation Function 2) sprawia, że ataki brute-force stają się trudniejsze, bo obliczenie klucza trwa dłużej.
    Sól zapobiega atakom tęczowych tablic (precomputed hashes).
    Duża liczba iteracji (100 000) zwiększa bezpieczeństwo, utrudniając ataki słownikowe.

🔐 2. Szyfrowanie pliku

🔹 Tworzymy losową IV (inicjalizującą wektor) – 16 bajtów.
🔹 Czytamy zawartość pliku i dodajemy padding (bo AES-CBC działa na blokach 16 bajtów).
🔹 Tworzymy szyfr AES-CBC i szyfrujemy dane.
🔹 Zapisujemy zaszyfrowane dane w pliku w następującej strukturze:

[SÓL (16 bajtów)][IV (16 bajtów)][SZYFROGRAM (reszta pliku)]

📌 Kod odpowiedzialny za to:

def encrypt_file(input_file: str, output_file: str, password: str):
    """Szyfruje plik AES-256 w trybie CBC."""
    salt = os.urandom(SALT_SIZE)  # Generujemy losową sól
    iv = os.urandom(IV_SIZE)  # Generujemy losowy wektor IV
    key = derive_key(password, salt)  # Generujemy klucz na podstawie hasła i soli

    with open(input_file, 'rb') as f:
        plaintext = f.read()
    
    # Padding - AES wymaga bloków 16-bajtowych
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len]) * pad_len
    
    # Tworzymy szyfr AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Zapisujemy sól, IV i zaszyfrowane dane do pliku
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    print(f"Plik zaszyfrowany: {output_file}")

📌 Dlaczego tak?

    Sól i IV są losowe – każda sesja szyfrowania daje inny wynik, nawet dla tego samego pliku i hasła.
    AES-CBC zapewnia silne bezpieczeństwo, ale wymaga IV, który nie może się powtarzać.
    Padding (PKCS7) pozwala AES działać na danych o dowolnej długości.

🔓 3. Odszyfrowanie pliku

🔹 Odczytujemy sól i IV z zaszyfrowanego pliku.
🔹 Ponownie generujemy klucz na podstawie hasła i soli.
🔹 Odszyfrowujemy dane przy użyciu AES-CBC.
🔹 Usuwamy padding i zapisujemy odszyfrowany plik.

📌 Kod odpowiedzialny za to:

def decrypt_file(input_file: str, output_file: str, password: str):
    """Deszyfruje plik AES-256 w trybie CBC."""
    with open(input_file, 'rb') as f:
        data = f.read()
    
    # Odczytujemy sól, IV i szyfrogram
    salt, iv, ciphertext = data[:SALT_SIZE], data[SALT_SIZE:SALT_SIZE+IV_SIZE], data[SALT_SIZE+IV_SIZE:]
    key = derive_key(password, salt)  # Generujemy klucz ponownie

    # Tworzymy szyfr AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Usuwamy padding
    pad_len = plaintext[-1]
    plaintext = plaintext[:-pad_len]
    
    # Zapisujemy odszyfrowany plik
    with open(output_file, 'wb') as f:
        f.write(plaintext)
    
    print(f"Plik odszyfrowany: {output_file}")

📌 Dlaczego tak?

    Klucz jest dynamicznie obliczany na podstawie hasła i soli, więc nie ma potrzeby go przechowywać.
    Bez poprawnego hasła nie można odszyfrować pliku, nawet jeśli zna się sól i IV.
    Padding musi zostać usunięty, ponieważ AES-CBC działa na blokach 16-bajtowych.

📂 Szyfrowanie katalogu

Katalogi są szyfrowane rekurencyjnie, czyli każdy plik w katalogu jest traktowany osobno.

📌 Kod odpowiedzialny za szyfrowanie katalogu:

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

🔎 Podsumowanie

    Hasło + sól → klucz (AES-256) (dynamicznie generowany).
    Sól i IV są zapisywane w zaszyfrowanym pliku (ale klucz nigdy!).
    Każde szyfrowanie jest unikalne (dzięki losowej soli i IV).
    Bez poprawnego hasła nie odszyfrujesz pliku (bo klucz nie jest przechowywany).
    Nie trzeba przechowywać kluczy – są odtwarzane z hasła i soli.

Dzięki temu rozwiązanie jest bezpieczne, proste i skalowalne. 🚀

Szyfrowanie pliku:
python app.py encrypt plik.txt plik.enc

Szyfrowanie katalogu:
python app.py encrypt /home/greg/katalog katalog.enc
python app.py encrypt katalog katalog.enc # katalog w tym samym miejscu co program

Deszyfrowanie pliku:
python app.py decrypt plik.enc plik.txt

Deszyfrowanie katalogu
python app.py decrypt /home/greg/katalog.enc katalog
python app.py decrypt katalog.enc katalog # katalog w tym samym miejscu co program


