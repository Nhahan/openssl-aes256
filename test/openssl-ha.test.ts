import { encryptAes256, decryptAes256, encryptHs256 } from '../src/openssl-ha';

describe('Encryption and Hashing Functions', () => {

    const message: string = 'Hello, World!';
    const key: string = 'secretpassword';
    const ciphertext: string = 'SOME_BASE64_ENCODED_CIPHERTEXT';
    const secret: string = 'secretpassword';

    describe('encryptAes256', () => {
        it('should encrypt the message with the given key', () => {
            const encrypted: string = encryptAes256(message, key);
            expect(encrypted).toBeTruthy();
            expect(typeof encrypted).toBe('string');
        });

        it('should throw an error if message is missing', () => {
            expect(() => {
                encryptAes256(undefined, key);
            }).toThrow('Missing message');
        });

        it('should throw an error if key is missing', () => {
            expect(() => {
                encryptAes256(message, undefined);
            }).toThrow('Missing key');
        });
    });

    describe('decryptAes256', () => {
        it('should decrypt the ciphertext with the given key', () => {
            const decrypted: string = decryptAes256(ciphertext, key);
            expect(decrypted).toBeTruthy();
            expect(typeof decrypted).toBe('string');
        });

        it('should throw an error if ciphertext is missing', () => {
            expect(() => {
                decryptAes256(undefined, key);
            }).toThrow('Missing ciphertext');
        });

        it('should throw an error if key is missing', () => {
            expect(() => {
                decryptAes256(ciphertext, undefined);
            }).toThrow('Missing key');
        });
    });

    describe('encryptHs256', () => {
        it('should generate the HMAC-SHA256 hash of the data using the secret', () => {
            const hashed: string = encryptHs256(message, secret);
            expect(hashed).toBeTruthy();
            expect(typeof hashed).toBe('string');
        });

        it('should throw an error if data is missing', () => {
            expect(() => {
                encryptHs256(undefined, secret);
            }).toThrow('Missing data');
        });

        it('should throw an error if secret is missing', () => {
            expect(() => {
                encryptHs256(message, undefined);
            }).toThrow('Missing secret');
        });
    });
});
