#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <openssl/evp.h>

typedef unsigned char U8;

#define BLOCK_SIZE 16
#define KEY_SIZE 32

void adjust_key_length(const U8 *src_key, size_t src_key_length, U8 *adjusted_key) {
    size_t key_length = (src_key_length < KEY_SIZE) ? KEY_SIZE : src_key_length;
    memcpy(adjusted_key, src_key, key_length);
    if (src_key_length < KEY_SIZE) {
        memset(adjusted_key + src_key_length, 0, KEY_SIZE - src_key_length);
    }
}

void adjust_iv_from_key(const U8 *key, U8 *iv) {
    memcpy(iv, key, BLOCK_SIZE);
}

void aes256_cbc_encrypt(const U8 *message, const U8 *key, const U8 *iv, U8 *ciphertext, size_t size, int *ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, message, (int)size);
    *ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    *ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void aes256_cbc_decrypt(const U8 *ciphertext, const U8 *key, const U8 *iv, U8 *message, size_t size, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int decrypted_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, message, &len, ciphertext, ciphertext_len);
    decrypted_len += len;
    EVP_DecryptFinal_ex(ctx, message + decrypted_len, &len);
    decrypted_len += len;
    EVP_CIPHER_CTX_free(ctx);

    message[decrypted_len] = '\0';
}

int main(int argc, char *args[]) {
    setlocale(LC_ALL, "");

    U8 message[1024];
    U8 key[KEY_SIZE];
    U8 iv[BLOCK_SIZE];
    U8 ciphertext[1024];
    U8 decrypted[1024];
    int ciphertext_len = 0;

    printf("Enter the message to encrypt: ");
    fgets((char *)message, sizeof(message), stdin);
    printf("Enter the key (up to 32 bytes): ");
    fgets((char *)key, sizeof(key), stdin);

    size_t message_length = strlen((char *)message);
    adjust_key_length(key, strlen((char *)key), key);
    adjust_iv_from_key(key, iv);

    message[strcspn((char *)message, "\n")] = '\0';

    aes256_cbc_encrypt(message, key, iv, ciphertext, message_length, &ciphertext_len);
    aes256_cbc_decrypt(ciphertext, key, iv, decrypted, sizeof(decrypted), ciphertext_len);

    printf("Decrypted message: %s\n", decrypted);

    return 0;
}
