#include <node_api.h>
#include <string.h>
#include <openssl/hmac.h>

napi_value HS256(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

    char message[256];
    size_t message_len;
    napi_get_value_string_utf8(env, argv[0], message, 256, &message_len);

    char key[256];
    size_t key_len;
    napi_get_value_string_utf8(env, argv[1], key, 256, &key_len);

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;

    HMAC(EVP_sha256(), key, key_len, (unsigned char*)message, message_len, digest, &digest_len);

    napi_value result;
    napi_create_arraybuffer(env, digest_len, (void*)digest, NULL, &result);

    return result;
}

napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, NULL, 0, HS256, NULL, &fn);
    napi_set_named_property(env, exports, "HS256", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)