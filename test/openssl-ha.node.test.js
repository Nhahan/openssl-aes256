const addon = require('../src/openssl-ha.node');

describe('Native Addon', () => {
    const message = 'Hello, World!';
    const key = '12345678901234567890123456789012';

    test('The decrypted message should be the same as the original message before encryption', () => {
        const encrypted = addon.encryptAes256(message, key);
        const decrypted = addon.decryptAes256(encrypted, key);
        console.log('encrypted: ', encrypted, '\ndecrypted: ', decrypted);

        expect(decrypted).toEqual(message);
    });

    test('Generates HMAC correctly', () => {
        const encrypted = addon.encryptHs256(message, key);
        console.log('encrypted: ', encrypted);

        expect(encrypted).toBeDefined();
        expect(typeof encrypted).toBe('string');
    });
});