{
  "targets": [
    {
      "target_name": "binding",
      "sources": [ "hs256.c" ],
      "cflags": [ "-I/opt/homebrew/opt/openssl@3/include" ],
      "ldflags": [ "-L/opt/homebrew/opt/openssl@3/lib" ],
      "libraries": [ "-lcrypto", "-lssl" ],
      "include_dirs": [ "<!(node -e \"require('node-addon-api').include\")" ],
      "dependencies": [ "<!(node -e \"require('node-addon-api').gyp\")" ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS" ]
    }
  ]
}
