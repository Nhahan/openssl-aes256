#include <node_api.h>
#include <string.h>
#include <openssl/hmac.h>

typedef struct {
    napi_deferred deferred;
    napi_async_work work;
    unsigned char* digest;
    unsigned int digest_len;
    char* message;
    size_t message_len;
    char* key;
    size_t key_len;
    int status;
} hmac_request;

void execute_hmac(napi_env env, void* data) {
    hmac_request* req = (hmac_request*)data;
    req->digest = HMAC(EVP_sha256(), req->key, req->key_len, (unsigned char*)req->message, req->message_len, NULL, &(req->digest_len));
    req->status = (req->digest != NULL ? 0 : 1);
}

void complete_hmac(napi_env env, napi_status status, void* data) {
    hmac_request* req = (hmac_request*)data;

    if (status == napi_ok) {
        if (req->status == 0) {
            napi_value result;
            napi_create_external_arraybuffer(env, req->digest_len, req->digest, free, NULL, &result);
            napi_resolve_deferred(env, req->deferred, result);
        } else {
            napi_value error;
            napi_create_string_utf8(env, "Failed to compute HMAC", NAPI_AUTO_LENGTH, &error);
            napi_reject_deferred(env, req->deferred, error);
        }
    } else {
        napi_value error;
        napi_create_string_utf8(env, "Failed to complete HMAC computation", NAPI_AUTO_LENGTH, &error);
        napi_reject_deferred(env, req->deferred, error);
    }

    napi_delete_async_work(env, req->work);
    free(req);
}

napi_value HS256(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value argv[2];
    napi_status status;

    status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
    if (status != napi_ok) {
        napi_throw_error(env, NULL, "Failed to parse arguments");
        return NULL;
    }

    hmac_request* req = (hmac_request*)malloc(sizeof(hmac_request));

    status = napi_get_value_string_utf8(env, argv[0], NULL, 0, &(req->message_len));
    if (status != napi_ok) {
        free(req);
        napi_throw_error(env, NULL, "Failed to get message length");
        return NULL;
    }

    req->message = (char*)malloc(req->message_len + 1);
    status = napi_get_value_string_utf8(env, argv[0], req->message, req->message_len + 1, &(req->message_len));
    if (status != napi_ok) {
        free(req->message);
        free(req);
        napi_throw_error(env, NULL, "Failed to get message");
        return NULL;
    }

    status = napi_get_value_string_utf8(env, argv[1], NULL, 0, &(req->key_len));
    if (status != napi_ok) {
        free(req->message);
        free(req);
        napi_throw_error(env, NULL, "Failed to get key length");
        return NULL;
    }

    req->key = (char*)malloc(req->key_len + 1);
    status = napi_get_value_string_utf8(env, argv[1], req->key, req->key_len + 1, &(req->key_len));
    if (status != napi_ok) {
        free(req->message);
        free(req->key);
        free(req);
        napi_throw_error(env, NULL, "Failed to get key");
        return NULL;
    }

    napi_value promise;
    napi_create_promise(env, &(req->deferred), &promise);

    napi_create_async_work(env, NULL, napi_create_string_utf8(env, "HMAC work", NAPI_AUTO_LENGTH, NULL), execute_hmac, complete_hmac, req, &(req->work));
    napi_queue_async_work(env, req->work);

    return promise;
}

napi_value Init(napi_env env, napi_value exports) {
    napi_value fn;
    napi_create_function(env, NULL, 0, HS256, NULL, &fn);
    napi_set_named_property(env, exports, "HS256", fn);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
