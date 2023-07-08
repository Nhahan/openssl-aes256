import { encryptAes256, decryptAes256, encryptHs256 } from '../src/openssl-ha';

describe('OpenSSL-HA', () => {
    const validMessage = 'Hello, World!';
    const validKey = '0123456789abcdef0123456789abcdef';

    describe('encryptAes256', () => {
        test('should encrypt the message with a valid key', () => {
            const encrypted = encryptAes256(validMessage, validKey);
            expect(encrypted).toBeDefined();
            expect(encrypted).not.toBe(validMessage);
        });

        test('should throw an error for invalid message', () => {
            const invalidMessage = null;
            expect(() => {
                encryptAes256(invalidMessage, validKey);
            }).toThrow('Invalid message');
        });

        test('should throw an error for invalid key', () => {
            const invalidKey = null;
            expect(() => {
                encryptAes256(validMessage, invalidKey);
            }).toThrow('Invalid key');
        });
    });

    describe('decryptAes256', () => {
        test('should decrypt the ciphertext with a valid key', () => {
            const encrypted = encryptAes256(validMessage, validKey);
            const decrypted = decryptAes256(encrypted, validKey);
            expect(decrypted).toBe(validMessage);
        });
    });

    describe('encryptHs256', () => {
        test('should throw an error for invalid message', () => {
            const invalidMessage = null;
            expect(() => {
                encryptHs256(invalidMessage, validKey);
            }).toThrow('Invalid message');
        });

        test('should encrypt the message with a valid key', () => {
            const encrypted = encryptHs256(validMessage, validKey);
            expect(encrypted).toBeDefined();
            expect(encrypted).not.toBe(validMessage);
        });
    });
});
