{
    "targets": [
        {
            "target_name": "aes256",
            "sources": ["aes256.c"],
            "cflags": ["-I/opt/homebrew/opt/openssl@3/include"],
            "ldflags": ["-L/opt/homebrew/opt/openssl@3/lib"],
            "libraries": ["-lcrypto"],
            "include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
            "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"]
        }
    ]
}
