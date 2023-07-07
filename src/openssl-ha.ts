const addon = require('./openssl-ha.node');

export function hmac(data: string, secret: string): string {
    return addon.hmac(data, secret);
}

export function encrypt(message: string, key: string): string {
    const encryptedBuffer = addon.encrypt(message, key);
    return encryptedBuffer.toString('base64');
}

export function decrypt(encrypted: string, key: string): string {
    const encryptedBuffer = Buffer.from(encrypted, 'base64');
    const decryptedBuffer = addon.decrypt(encryptedBuffer, key);
    return decryptedBuffer.toString('utf8');
}
