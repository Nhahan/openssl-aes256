# OpenSSL-HA

OpenSSL-HA is based off of the native OpenSSL library and will provide functionality of the widely adopted AES-256 and HS-256 algorithms.

## Features

- AES-256 encryption and decryption
- HS-256 hashing

## Installation

```bash
npm install openssl-ha
```

## Usage

```ts
import { encryptAes256, decryptAes256, encryptHs256 } from 'openssl-ha';

// Encrypt a message with AES-256
const message = 'Hello, World!';
const key = '3nCrYpT10nK3y!';
const encryptedMessage = encryptAes256(message, key);
console.log('Encrypted Message:', encryptedMessage);

// Decrypt the encrypted message with AES-256
const decryptedMessage = decryptAes256(encryptedMessage, key);
console.log('Decrypted Message:', decryptedMessage);

// Generate an HS-256 hash
const hash = encryptHs256(message, key);
console.log('Hash:', hash);
```

- *Note: Versions lower than 3.0.0 are not recommended*

## API

- `encryptAes256(message: string, key: string): string`  
    - Encrypts a message using the AES-256 algorithm with the provided key and returns the encrypted ciphertext.

- `decryptAes256(ciphertext: string, key: string): string`  
    - Decrypts a ciphertext using the AES-256 algorithm with the provided key and returns the original message.

- `encryptHs256(message: string, key: string): string`  
    - Generates an HS-256 hash of the message using the provided key and returns the hash value.

## License

This project is licensed under the MIT License.
