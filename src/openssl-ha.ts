const addon = require('./openssl-ha.node');

export function encryptAes256(message: string, key: string): string {
    const encryptedBuffer = addon.encryptAes256(message, key);
    return encryptedBuffer.toString('base64');
}

export function decryptAes256(ciphertext: string, key: string): string {
    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const decryptedBuffer = addon.decryptAes256(ciphertextBuffer, key);
    return decryptedBuffer.toString('utf8');
}

export function encryptHs256(data: string, secret: string): string {
    return addon.encryptHs256(data, secret);
}
