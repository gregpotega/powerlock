Audyt

Kod w pliku powerlock.py implementuje narzędzie do szyfrowania i deszyfrowania plików oraz katalogów przy użyciu algorytmu AES-256 w trybie CBC z dodatkowym HMAC dla integralności danych. Oto szczegółowa analiza zabezpieczeń i ogólna ocena kodu:

### Zabezpieczenia

1. **Generowanie klucza**:
   - Funkcja `derive_key` generuje klucz szyfrowania na podstawie hasła użytkownika i losowej soli przy użyciu PBKDF2-HMAC-SHA256. 
   - Użycie soli i dużej liczby iteracji (100 000) zwiększa bezpieczeństwo, utrudniając ataki brute-force i ataki tęczowych tablic.

2. **Szyfrowanie plików**:
   - Funkcja `encrypt_file` szyfruje pliki przy użyciu AES-256 w trybie CBC.
   - Generowane są losowe wartości soli i IV dla każdego pliku, co zapewnia unikalność szyfrowania nawet dla tych samych danych.
   - Dodawany jest padding do danych, aby były wielokrotnością 16 bajtów.
   - HMAC jest używany do zapewnienia integralności zaszyfrowanych danych.

3. **Deszyfrowanie plików**:
   - Funkcja `decrypt_file` deszyfruje pliki, weryfikując integralność danych za pomocą HMAC.
   - Klucz jest ponownie generowany na podstawie hasła i soli.
   - Padding jest usuwany po deszyfrowaniu.

4. **Szyfrowanie i deszyfrowanie katalogów**:
   - Funkcje `encrypt_directory` i `decrypt_directory` rekurencyjnie szyfrują i deszyfrują wszystkie pliki w katalogu.

5. **Atrybuty plików**:
   - Funkcje `set_readonly` i `remove_readonly` ustawiają i usuwają atrybut tylko do odczytu dla plików, co może zapobiec przypadkowemu usunięciu lub modyfikacji zaszyfrowanych plików.

### Ocena kodu

1. **Bezpieczeństwo**:
   - Kod jest dobrze zabezpieczony, używając silnych algorytmów kryptograficznych (AES-256, HMAC-SHA256) i technik (PBKDF2, losowe IV i sól).
   - Użycie HMAC zapewnia integralność danych, co jest ważne w kontekście szyfrowania.

2. **Czytelność i struktura**:
   - Kod jest dobrze zorganizowany i czytelny, z odpowiednimi komentarzami i dokumentacją.
   - Funkcje są dobrze podzielone na mniejsze, odpowiedzialne za konkretne zadania, co ułatwia zrozumienie i utrzymanie kodu.

3. **Użyteczność**:
   - Program oferuje przydatne funkcje szyfrowania i deszyfrowania zarówno plików, jak i katalogów.
   - Interfejs wiersza poleceń jest intuicyjny i dobrze udokumentowany.

4. **Potencjalne ulepszenia**:
   - Można rozważyć dodanie obsługi wyjątków dla bardziej szczegółowego raportowania błędów.
   - Można dodać testy jednostkowe, aby zapewnić poprawność działania funkcji.

Ogólnie rzecz biorąc, kod jest solidny, dobrze zabezpieczony i dobrze napisany. Spełnia swoje zadanie w sposób efektywny i bezpieczny.

### Opis testów jednostkowych

- **setUp**: Tworzy tymczasowy katalog i plik testowy przed każdym testem.
- **tearDown**: Usuwa tymczasowy katalog po każdym teście.
- **test_set_readonly**: Sprawdza, czy plik jest ustawiony jako tylko do odczytu.
- **test_remove_readonly**: Sprawdza, czy atrybut tylko do odczytu jest usunięty.
- **test_encrypt_file**: Sprawdza, czy plik jest zaszyfrowany.
- **test_decrypt_file**: Sprawdza, czy plik jest odszyfrowany i jego zawartość jest zgodna z oryginałem.
- **test_encrypt_directory**: Sprawdza, czy katalog jest zaszyfrowany.
- **test_decrypt_directory**: Sprawdza, czy katalog jest odszyfrowany i jego zawartość jest zgodna z oryginałem.



