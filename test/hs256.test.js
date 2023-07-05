const addon = require('../src/hs256.node');

describe('Native Addon', () => {
    test('Encrypts and decrypts the message correctly', () => {
        const message = 'Hello, World!';
        const key = 'mySecretKey';

        const encrypted = addon.encrypt(message, key);
        const decrypted = addon.decrypt(encrypted, key);

        expect(decrypted).toEqual(message);
    });
});
