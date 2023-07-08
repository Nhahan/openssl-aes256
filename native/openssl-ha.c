#include <node_api.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

typedef unsigned char U8;

#define MAX_BUFFER_SIZE 1024
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
    EVP_CIPHER_CTX_cleanup(ctx);
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
    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    message[decrypted_len] = '\0';
}

napi_value Encrypt(napi_env env, napi_callback_info info) {
    napi_status status;

    size_t argc = 2;
    napi_value argv[2];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok || argc < 2) {
        napi_throw_error(env, NULL, "Invalid arguments.");
        return NULL;
    }

    char message[MAX_BUFFER_SIZE];
    size_t message_length = 0;
    status = napi_get_value_string_utf8(env, argv[0], message, sizeof(message), &message_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid message.");
        return NULL;
    }

    char key[KEY_SIZE];
    size_t key_length = 0;
    status = napi_get_value_string_utf8(env, argv[1], key, sizeof(key), &key_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid key.");
        return NULL;
    }

    U8 adjusted_key[KEY_SIZE];
    adjust_key_length((U8 *)key, key_length, adjusted_key);

    U8 iv[BLOCK_SIZE];
    adjust_iv_from_key(adjusted_key, iv);

    EVP_CIPHER_CTX *ctx;
    int ciphertext_len = 0;
    int len;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        napi_throw_error(env, NULL, "Failed to create encryption context.");
        return NULL;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, adjusted_key, iv)) {
        napi_throw_error(env, NULL, "Failed to initialize encryption.");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (message_length >= MAX_BUFFER_SIZE) {
        napi_throw_error(env, NULL, "Message size exceeds buffer capacity.");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    size_t ciphertext_size = message_length + EVP_CIPHER_CTX_block_size(ctx);
    U8 *ciphertext = (U8 *)malloc(ciphertext_size);
    if (ciphertext == NULL) {
        napi_throw_error(env, NULL, "Memory allocation failed.");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (U8 *)message, (int)message_length)) {
        napi_throw_error(env, NULL, "Error occurred during encryption.");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        napi_throw_error(env, NULL, "Error occurred during encryption finalization.");
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_cleanup(ctx);
    EVP_CIPHER_CTX_free(ctx);

    napi_value result;
    status = napi_create_buffer_copy(env, ciphertext_len, ciphertext, NULL, &result);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result buffer.");
        free(ciphertext);
        return NULL;
    }

    free(ciphertext);

    return result;
}

napi_value Decrypt(napi_env env, napi_callback_info info) {
    napi_status status;
    size_t argc = 2;
    napi_value argv[2];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok || argc < 2) {
        napi_throw_error(env, NULL, "Invalid arguments");
        return NULL;
    }

    size_t ciphertext_length;
    status = napi_get_buffer_info(env, argv[0], NULL, &ciphertext_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid ciphertext");
        return NULL;
    }

    U8* ciphertext;
    status = napi_get_buffer_info(env, argv[0], (void**)&ciphertext, &ciphertext_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to get ciphertext buffer");
        return NULL;
    }

    char key[KEY_SIZE];
    size_t key_length = 0;
    status = napi_get_value_string_utf8(env, argv[1], key, sizeof(key), &key_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid key");
        return NULL;
    }

    U8 adjusted_key[KEY_SIZE];
    adjust_key_length((U8 *)key, key_length, adjusted_key);

    U8 iv[BLOCK_SIZE];
    adjust_iv_from_key(adjusted_key, iv);

    U8 decrypted[MAX_BUFFER_SIZE];
    aes256_cbc_decrypt(ciphertext, adjusted_key, iv, decrypted, sizeof(decrypted), ciphertext_length);

    napi_value result;
    status = napi_create_string_utf8(env, (char *)decrypted, strlen((char *)decrypted), &result);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result string");
        return NULL;
    }

    return result;
}

napi_value Hmac(napi_env env, napi_callback_info info) {
    napi_status status;

    size_t argc = 2;
    napi_value argv[2];
    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok || argc < 2) {
        napi_throw_error(env, NULL, "Invalid arguments");
        return NULL;
    }

    char message[1024];
    size_t message_length = 0;
    status = napi_get_value_string_utf8(env, argv[0], message, sizeof(message), &message_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid message");
        return NULL;
    }

    char secret[1024];
    size_t secret_length = 0;
    status = napi_get_value_string_utf8(env, argv[1], secret, sizeof(secret), &secret_length);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Invalid secret");
        return NULL;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_length;

    HMAC(EVP_sha256(), secret, secret_length, (unsigned char*)message, message_length, digest, &digest_length);

    char result[(EVP_MAX_MD_SIZE * 2) + 1];
    for (unsigned int i = 0; i < digest_length; ++i) {
        sprintf(&result[i * 2], "%02x", (unsigned int)digest[i]);
    }

    napi_value result_value;
    status = napi_create_string_utf8(env, result, digest_length * 2, &result_value);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to create result string");
        return NULL;
    }

    return result_value;
}

napi_value Init(napi_env env, napi_value exports) {
    napi_status status;

    napi_property_descriptor desc[] = {
        {"encryptAes256", NULL, Encrypt, NULL, NULL, NULL, napi_default, NULL},
        {"decryptAes256", NULL, Decrypt, NULL, NULL, NULL, napi_default, NULL},
        {"encryptHs256", NULL, Hmac, NULL, NULL, NULL, napi_default, NULL},
    };

    status = napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to define properties");
        return NULL;
    }

    return exports;
}

NAPI_MODULE(openssl_ha, Init);
