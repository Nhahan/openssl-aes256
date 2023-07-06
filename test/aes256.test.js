const addon = require('../src/aes256.node');

describe('Native Addon', () => {
    test('Encrypts and decrypts the message correctly', () => {
        const message = 'Hello, World!';
        const key = '12345678901234567890123456789012';

        const encrypted = addon.encrypt(message, key);
        const decrypted = addon.decrypt(encrypted, key);

        expect(decrypted).toEqual(message);
    });
});

function btoa(str) {
    return Buffer.from(str, 'binary').toString('base64');
}

function atob(str) {
    return Buffer.from(str, 'base64').toString('binary');
}