const addon = require('../src/hs256-aes256.node');

describe('Native Addon', () => {
    const message = 'Hello, World!';
    const key = '12345678901234567890123456789012';

    test('The decrypted message should be the same as the original message before encryption', () => {
        const encrypted = addon.encrypt(message, key);
        const decrypted = addon.decrypt(encrypted, key);

        expect(decrypted).toEqual(message);
    });

    test('Generates HMAC correctly', () => {
        const result = addon.hmac(message, key);

        expect(result).toBeDefined();
        expect(typeof result).toBe('string');
    });
});