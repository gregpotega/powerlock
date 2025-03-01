#!/bin/bash

APP_NAME="powerlock"
VERSION="1.0"
ARCH="all"
DEB_DIR="${APP_NAME}_${VERSION}"
BIN_DIR="${DEB_DIR}/usr/local/bin"
DEBIAN_DIR="${DEB_DIR}/DEBIAN"

echo "[+] Czyszczenie poprzednich plików..."
rm -rf "$DEB_DIR" "${APP_NAME}_*.deb"

echo "[+] Tworzenie struktury katalogów..."
mkdir -p "$BIN_DIR" "$DEBIAN_DIR"

echo "[+] Tworzenie pliku DEBIAN/control..."
cat <<EOF > "$DEBIAN_DIR/control"
Package: $APP_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCH
Depends: python3, python3-cryptography
Maintainer: Greg <potegagreg@gmail.com>
Description: File encryption program in Python.
EOF

echo "[+] Tworzenie pliku DEBIAN/postinst..."
cat <<EOF > "$DEBIAN_DIR/postinst"
#!/bin/bash
chmod +x /usr/local/bin/$APP_NAME
echo "$APP_NAME został zainstalowany!"
EOF
chmod 755 "$DEBIAN_DIR/postinst"

echo "[+] Kopiowanie skryptu..."
if [[ ! -f "powerlock.py" ]]; then
    echo "[!] Błąd: Plik powerlock.py nie istnieje w katalogu!"
    exit 1
fi
cp powerlock.py "$BIN_DIR/$APP_NAME"
chmod 755 "$BIN_DIR/$APP_NAME"

echo "[+] Budowanie pakietu .deb..."
dpkg-deb --build "$DEB_DIR"
if [[ $? -ne 0 ]]; then
    echo "[!] Błąd: dpkg-deb nie powiodło się!"
    exit 1
fi

mv "${DEB_DIR}.deb" "${APP_NAME}_${VERSION}.deb"
echo "[+] Pakiet ${APP_NAME}_${VERSION}.deb został wygenerowany!"
echo "[+] Instalacja: sudo dpkg -i ${APP_NAME}_${VERSION}.deb"

