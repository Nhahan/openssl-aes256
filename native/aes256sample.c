#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <openssl/evp.h>

typedef unsigned char U8;

#define BLOCK_SIZE 16
#define KEY_SIZE 32

void adjust_key_length(const U8 *src_key, U8 *adjusted_key) {
    size_t src_key_length = strlen((char *)src_key);
    size_t key_length = (src_key_length < KEY_SIZE) ? KEY_SIZE : src_key_length;
    memcpy(adjusted_key, src_key, key_length);
    if (src_key_length < KEY_SIZE) {
        memset(adjusted_key + src_key_length, 0, KEY_SIZE - src_key_length);
    }
}

void adjust_iv_from_key(const U8 *key, U8 *iv) {
    memcpy(iv, key, BLOCK_SIZE);
}

void aes256_cbc_encrypt(const U8 *message, const U8 *key, const U8 *iv, U8 *ciphertext, size_t size) {
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, message, (int)size);
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

void aes256_cbc_decrypt(const U8 *ciphertext, const U8 *key, const U8 *iv, U8 *message, size_t size) {
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, message, &len, ciphertext, (int)size);
    EVP_DecryptFinal_ex(ctx, message + len, &len);
    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *args[]) {
    setlocale(LC_ALL, "");

    U8 message[1024];
    U8 key[KEY_SIZE];
    U8 iv[BLOCK_SIZE];
    U8 ciphertext[1024];
    U8 decrypted[1024];

    printf("Enter the message to encrypt: ");
    fgets((char *)message, sizeof(message), stdin);
    printf("Enter the key (up to 32 bytes): ");
    fgets((char *)key, sizeof(key), stdin);

    adjust_key_length(key, key);
    adjust_iv_from_key(key, iv);

    message[strcspn((char *)message, "\n")] = '\0';

    aes256_cbc_encrypt(message, key, iv, ciphertext, sizeof(message));

    int decrypted_len = 0;
    int len = 0;
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &decrypted_len, ciphertext, (int)strlen((char *)ciphertext));
    EVP_DecryptFinal_ex(ctx, decrypted + decrypted_len, &len);
    decrypted[decrypted_len + len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    printf("Decrypted message: %s\n", decrypted);
    return 0;
}
