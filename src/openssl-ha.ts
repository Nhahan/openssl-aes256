const addon = require('./openssl-ha.node');

export function encryptAes256(message: string, key: string): string {
    if (!message) throw new Error('Missing message');
    if (!key) throw new Error('Missing key');

    const MAX_MESSAGE_LENGTH = 1024;
    const MAX_KEY_LENGTH = 32;

    const truncatedMessage = message.slice(0, MAX_MESSAGE_LENGTH);
    const truncatedKey = key.slice(0, MAX_KEY_LENGTH);

    const encryptedBuffer = addon.encryptAes256(truncatedMessage, truncatedKey);
    return encryptedBuffer.toString('base64');
}

export function decryptAes256(ciphertext: string, key: string): string {
    if (!ciphertext) throw new Error('Missing ciphertext');
    if (!key) throw new Error('Missing key');

    const MAX_CIPHERTEXT_LENGTH = 1024;
    const MAX_KEY_LENGTH = 32;

    const ciphertextBuffer = Buffer.from(ciphertext, 'base64');
    const truncatedKey = key.slice(0, MAX_KEY_LENGTH);

    const decryptedBuffer = addon.decryptAes256(ciphertextBuffer.slice(0, MAX_CIPHERTEXT_LENGTH), truncatedKey);
    return decryptedBuffer.toString('utf8');
}

export function encryptHs256(data: string, secret: string): string {
    if (!data) throw new Error('Missing data');
    if (!secret) throw new Error('Missing secret');

    const MAX_DATA_LENGTH = 1024;
    const MAX_SECRET_LENGTH = 1024;

    const truncatedData = data.slice(0, MAX_DATA_LENGTH);
    const truncatedSecret = secret.slice(0, MAX_SECRET_LENGTH);

    return addon.encryptHs256(truncatedData, truncatedSecret);
}
