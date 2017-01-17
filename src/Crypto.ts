import { bytesToWebsafeBase64, websafeBase64ToBytes } from './Converters';

export interface ExternalKeyPair {
    algorithm: string; // 'ECDSA' or 'ECDH'
    publicKey: string; // base64URL-encoded public key (04 + x + y)
    wrappedPrivateKey: string; // base64URL-encoding of wrapped-jwk private key
    salt: string; // base64URL-encoded salt used for AES key derivation (using PBKDF2)
    rounds: number; // rounds of SHA256 used for AES key derivation
    iv: string; // base64URL-encoded initialization vector (12 bytes) used for key wrapping
}

export interface InternalKeyPair {
    pubKey: CryptoKey,
    privKey: CryptoKey
}

/**
 * SubtleCrypto boilerplate for methods used in
 * the ECDH and ECDSA authentication schemes.
 * 
 * @author Sam Claus
 * @version 1/17/17
 * @copyright Tera Insights, LLC
 */
export class Crypto {

    /**
     * Generates a SubtleCrypto key pair.
     * @param {string} algorithm The algorithm for which to produce a key pair.
     * @returns A promise fulfilling with a new key pair, or failing because a
     *          bad algorithm or bad uses were provided.
     */
    static generateKeys(algorithm: string): PromiseLike<CryptoKeyPair> {
        let usage: string = algorithm === 'ECDH' ? 'deriveKey' : 'sign';

        return crypto.subtle.generateKey({
            name: algorithm,
            namedCurve: 'P-256'
        }, true, [usage]).then(keyPair => {
            return keyPair;
        });
    }

    /**
     * Exports the given key pair, wrapping the private key using
     * an AES key derived with the given password, random salt, and a
     * random number of rounds of SHA-256.
     * @param {CryptoKey}  pubKey    SubtleCrypto public key.
     * @param {CryptoKey}  privKey   SubtleCrypto private key.
     * @param {string}     algorithm Key pair algorithm.
     * @param {Uint8Array} password  Password used to derive AES key
     *                               for wrapping. Wiped from memory
     *                               immediately following usage.
     * @returns A promise which fulfills with an external key pair.
     */
    static exportKeyPair(pubKey: CryptoKey, privKey: CryptoKey, algorithm: string,
        password: Uint8Array): PromiseLike<ExternalKeyPair> {
        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then(derivationKey => {
            password.fill(0, 0, password.length);

            let salt: ArrayBufferView = crypto.getRandomValues(new Uint8Array(16));
            let rounds: number = Math.floor(10000 * (0.9 + (Math.random() * 0.2))); // 10,000 ± 10%

            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: salt,
                iterations: rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                    name: 'AES-GCM',
                    length: 256
                }, false, ['wrapKey']).then(aesKey => {
                    let iv: ArrayBufferView = crypto.getRandomValues(new Uint8Array(12));

                    return crypto.subtle.wrapKey('jwk', privKey, aesKey, {
                        name: 'AES-GCM',
                        iv: iv,
                        additionalData: iv
                    } as any).then(wrappedPrivate => {
                        return crypto.subtle.exportKey('raw', pubKey).then(rawPublic => {
                            return {
                                algorithm: algorithm,
                                publicKey: bytesToWebsafeBase64(new Uint8Array(rawPublic)),
                                wrappedPrivateKey: bytesToWebsafeBase64(new Uint8Array(wrappedPrivate)),
                                salt: bytesToWebsafeBase64(new Uint8Array(salt.buffer)),
                                rounds: rounds,
                                iv: bytesToWebsafeBase64(new Uint8Array(iv.buffer))
                            };
                        });
                    });
                });
        });
    }

    /**
     * Imports client-side keys from an external key pair object.
     * @param {ExternalKeyPair} keyPair   The external key pair.
     * @param {Uint8Array}      password  Password used to derive AES key for
     *                                    unwrapping the private key. Wiped from
     *                                    memory immediately following usage.
     * @returns A promise which either fulfills upon successfully importing
     *          the key pair, or fails due to an incorrect password or a
     *          a flaw in the external key pair object.
     */
    static importKeyPair(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<InternalKeyPair> {
        let wrappedPrivate: Uint8Array = websafeBase64ToBytes(keyPair.wrappedPrivateKey);
        let usage: string = keyPair.algorithm === 'ECDH' ? 'deriveKey' : 'sign';

        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then(derivationKey => {
            password.fill(0, 0, password.length);

            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: websafeBase64ToBytes(keyPair.salt),
                iterations: keyPair.rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                    name: 'AES-GCM',
                    length: 256
                }, false, ['unwrapKey']).then(aesKey => {
                    let iv: ArrayBuffer = websafeBase64ToBytes(keyPair.iv).buffer;
                    return crypto.subtle.unwrapKey('jwk', wrappedPrivate, aesKey, {
                        name: 'AES-GCM',
                        iv: iv,
                        additionalData: iv
                    } as any, {
                        name: keyPair.algorithm,
                        namedCurve: 'P-256'
                    } as any, false, [usage]).then(unwrappedPrivate => {
                        return crypto.subtle.importKey('raw', websafeBase64ToBytes(keyPair.publicKey), {
                            name: keyPair.algorithm,
                            namedCurve: 'P-256'
                        }, true, []).then(publicKey => {
                            return {
                                pubKey: publicKey,
                                privKey: unwrappedPrivate
                            };
                        });
                    }, () => { throw new Error('User provided incorrect password!'); });
                });
        });
    }

    /**
     * Exports a P-256 public key from SubtleCrypto.
     * @param {CryptoKey} pubKey The key to export.
     * @returns A base64URL-encoded 65-byte public
     *          key: [04 + x + y].
     */
    static exportPublic(pubKey: CryptoKey): PromiseLike<string> {
        return crypto.subtle.exportKey('raw', pubKey).then(rawPublic => {
            return bytesToWebsafeBase64(new Uint8Array(rawPublic));
        });
    }

}