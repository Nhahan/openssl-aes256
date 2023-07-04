#include <node_api.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

void printErrorMessage(const char *message)
{
    fprintf(stderr, "Error: %s\n", message);
}

void encrypt(const char *plaintext, const char *key, char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printErrorMessage("Failed to create encryption context");
        return;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)key, (const unsigned char *)"00000000000000000000000000000000"))
    {
        printErrorMessage("Failed to initialize encryption operation");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)ciphertext, &len, (const unsigned char *)plaintext, strlen(plaintext)))
    {
        printErrorMessage("Failed to perform encryption");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char *)ciphertext + len, &len))
    {
        printErrorMessage("Failed to finalize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

void decrypt(const char *ciphertext, const char *key, char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        printErrorMessage("Failed to create decryption context");
        return;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char *)key, (const unsigned char *)"00000000000000000000000000000000"))
    {
        printErrorMessage("Failed to initialize decryption operation");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    BIO *bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO *bmem = BIO_new_mem_buf(ciphertext, -1);
    bmem = BIO_push(bio, bmem);

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)plaintext + plaintext_len, &len, NULL, 0))
    {
        printErrorMessage("Failed to perform decryption");
        EVP_CIPHER_CTX_free(ctx);
        BIO_free_all(bmem);
        return;
    }
    plaintext_len += len;

    if (1 != EVP_DecryptUpdate(ctx, (unsigned char *)plaintext + plaintext_len, &len, (unsigned char *)ciphertext, strlen(ciphertext)))
    {
        printErrorMessage("Failed to perform decryption");
        EVP_CIPHER_CTX_free(ctx);
        BIO_free_all(bmem);
        return;
    }
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + plaintext_len, &len))
    {
        printErrorMessage("Failed to finalize decryption");
        EVP_CIPHER_CTX_free(ctx);
        BIO_free_all(bmem);
        return;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    BIO_free_all(bmem);

    plaintext[plaintext_len] = '\0';
}

napi_value Encrypt(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 2;
    napi_value argv[2];

    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    char message[256];
    size_t message_len;
    status = napi_get_value_string_utf8(env, argv[0], message, sizeof(message), &message_len);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid message");
        return NULL;
    }

    char key[256];
    size_t key_len;
    status = napi_get_value_string_utf8(env, argv[1], key, sizeof(key), &key_len);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid key");
        return NULL;
    }

    char ciphertext[256];
    encrypt(message, key, ciphertext);

    napi_value result;
    status = napi_create_string_utf8(env, ciphertext, NAPI_AUTO_LENGTH, &result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Failed to create result string");
        return NULL;
    }

    return result;
}

napi_value Decrypt(napi_env env, napi_callback_info info)
{
    napi_status status;
    size_t argc = 2;
    napi_value argv[2];

    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    char ciphertext[256];
    size_t ciphertext_len;
    status = napi_get_value_string_utf8(env, argv[0], ciphertext, sizeof(ciphertext), &ciphertext_len);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid ciphertext");
        return NULL;
    }

    char key[256];
    size_t key_len;
    status = napi_get_value_string_utf8(env, argv[1], key, sizeof(key), &key_len);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Invalid key");
        return NULL;
    }

    char plaintext[256];
    decrypt(ciphertext, key, plaintext);

    napi_value result;
    status = napi_create_string_utf8(env, plaintext, NAPI_AUTO_LENGTH, &result);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Failed to create result string");
        return NULL;
    }

    return result;
}

napi_value Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_property_descriptor desc[] = {
        {"encrypt", NULL, Encrypt, NULL, NULL, NULL, napi_default, NULL},
        {"decrypt", NULL, Decrypt, NULL, NULL, NULL, napi_default, NULL},
    };

    status = napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
    if (status != napi_ok)
    {
        napi_throw_error(env, NULL, "Failed to define properties");
        return NULL;
    }

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
