const addon: any = require('./openssl-ha.node');
import { Buffer } from 'buffer';

export function encryptAes256(message: string, key: string): string {
    validateInput(message, 'Invalid message');
    validateInput(key, 'Invalid key');

    const ciphertext = addon.encryptAes256(message, key);
    return encodeBase64(ciphertext);
}

export function decryptAes256(ciphertext: string, key: string): string {
    validateInput(ciphertext, 'Invalid ciphertext');
    validateInput(key, 'Invalid key');

    const decodedCiphertext = decodeBase64(ciphertext);
    return addon.decryptAes256(decodedCiphertext, key);
}

export function encryptHs256(message: string, key: string): string {
    validateInput(message, 'Invalid message');
    validateInput(key, 'Invalid key');

    return addon.encryptHs256(message, key);
}

function validateInput(input: any, errorMessage: string): void {
    if (!input) {
        throw new Error(errorMessage);
    }
}

function encodeBase64(data: Buffer): string {
    return Buffer.from(data).toString('base64');
}

function decodeBase64(data: string): Buffer {
    return Buffer.from(data, 'base64');
}
