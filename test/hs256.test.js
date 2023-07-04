const addon = require('../src/hs256.node');

describe('Native Addon', () => {
    test('Encrypts and decrypts the message correctly', () => {
        const message = 'Hello, World!';
        const key = 'mySecretKey';

        // 암호화
        const encrypted = addon.encrypt(message, key);
        const encryptedBase64 = Buffer.from(encrypted).toString('base64');
        console.log(encryptedBase64);

        // 복호화
        const decrypted = addon.decrypt(encrypted, key);
        console.log(decrypted);

        // 결과 검증
        expect(decrypted).toEqual(message);
    });
});
