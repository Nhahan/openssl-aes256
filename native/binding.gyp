{
    "targets": [
        {
            "target_name": "hs256",
            "sources": [ "hs256.c" ],
            "libraries": [ "-lcrypto" ],
            "cflags": [ "-I/usr/include/openssl" ],
            "cflags!": [ "-fno-exceptions" ],
            "cflags_cc!": [ "-fno-exceptions" ],
            "include_dirs": ["<!(node -p \"require('node-addon-api').include\")"],
            "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"]
        }
    ]
}