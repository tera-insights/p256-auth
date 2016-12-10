import { Converters, bytesToWebsafeBase64, websafeBase64ToBytes } from './Converters';

interface ExternalKeyPair {
    publicKey: string; // base64URL-encoded public key (04 + x + y)
    wrappedPrivateKey: string; // base64URL-encoding of wrapped-jwk private key
    salt: string; // base64URL-encoded salt used for AES key derivation (using PBKDF2)
    rounds: number; // rounds of SHA256 used for AES key derivation
    iv: string; // base64URL-encoded initialization vector (12 bytes) used for key wrapping
}

/**
 * Stores session keys and generates HMAC messages
 * using them.
 * 
 * @author Sam Claus
 * @version 12/8/16
 * @copyright Tera Insights, LLC
 */
export class Authenticator {

    private clientPrivate: CryptoKey;
    private clientPublic: CryptoKey;
    private serverPublic: CryptoKey;

    /**
     * Generates a new ECDH key pair for the object. Must be
     * called before computing an HMAC.
     * @returns A promise fulfilling when key pair generation
     *          is finished.
     */
    generateKeyPair(): PromiseLike<void> {
        return crypto.subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, ['deriveKey']).then(keyPair => {
            this.clientPrivate = keyPair.privateKey;
            this.clientPublic = keyPair.publicKey;
            return;
        });
    }

    /**
     * Imports a server public key for ECDH.
     * @param {string} serverKey base64URL-encoded server
     *                           public key.
     * @returns A promise fulfilling when the server key
     *          has been successfully imported.
     */
    importServerKey(serverKey: string): PromiseLike<void> {
        let serverKeyRaw: Uint8Array = websafeBase64ToBytes(serverKey);

        return crypto.subtle.importKey('jwk', {
            kty: 'EC',
            crv: 'P-256',
            x: bytesToWebsafeBase64(serverKeyRaw.slice(1, 33)),
            y: bytesToWebsafeBase64(serverKeyRaw.slice(33, 65)),
            ext: false
        }, {
                name: 'ECDH',
                namedCurve: 'P-256'
            }, false, []).then(serverPubKey => {
                this.serverPublic = serverPubKey;
                return;
            });
    }

    /**
     * Computes an HMAC for the given message, using the server
     * and client keys to generate a secret and then hashing it
     * with the message. Results in an error if the Authenticator
     * object hasn't been fed a server public key and generated or
     * imported a client-side key pair.
     * @param {Uint8Array} message Bytes to sign.
     * @returns A promise which either fulfills with an HMAC
     *          signature, or fails because either a server key
     *          or client key pair were never provided.
     */
    computeHMAC(message: Uint8Array): PromiseLike<string> {
        return crypto.subtle.deriveKey({
            name: 'ECDH',
            namedCurve: 'P-256',
            public: this.serverPublic
        } as any, this.clientPrivate, {
                name: 'HMAC',
                length: 256
            }, false, []).then(secret => {
                return crypto.subtle.sign({
                    name: 'HMAC'
                } as any, secret, message).then(signedMessage => {
                    return bytesToWebsafeBase64(new Uint8Array(signedMessage));
                });
            });
    }

    /**
     * Exports the [04 + x + y] public key, encoded to base64URL,
     * for use server-side.
     * @returns A promise which either fulfills with the base64URL-encoded
     *          public key, or fail because no client key pair was provided.
     */
    getPublic(): PromiseLike<string> {
        return crypto.subtle.exportKey('raw', this.clientPublic)
            .then(rawPublic => {
                return bytesToWebsafeBase64(new Uint8Array(rawPublic));
            });
    }

    /**
     * Exports the client key pair, wrapping the private key using
     * an AES key derived with the given password, random salt, and a
     * random number of rounds of SHA-256.
     * @param {Uint8Array} password Password used to derive AES key
     *                              for wrapping. Wiped from memory
     *                              immediately following usage.
     * @returns A promise which either fulfills with an exported key,
     *          or fails because a bad password was provided or no
     *          keypair was generated.
     */
    exportKey(password: Uint8Array): PromiseLike<ExternalKeyPair> {
        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then((derivationKey: CryptoKey) => {
            password.fill(0, 0, password.length);

            let salt: ArrayBufferView = crypto.getRandomValues(new Uint8Array(16));
            let rounds: number = 10000 * (0.9 + (Math.random() * 0.2)); // 10,000 ± 10%

            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: salt,
                iterations: rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                    name: 'AES-GCM',
                    length: 256
                }, false, ['wrapKey']).then((aesKey: CryptoKey) => {
                    let iv: ArrayBufferView = crypto.getRandomValues(new Uint8Array(12));

                    return crypto.subtle.wrapKey('jwk', this.clientPrivate, aesKey, {
                        name: 'AES-GCM',
                        iv: iv, // not included in typings, so cast to 'any'
                        additionalData: iv
                    } as any).then(wrappedPrivate => {
                        return this.getPublic().then(extPublic => {
                            return {
                                publicKey: extPublic,
                                wrappedPrivateKey: bytesToWebsafeBase64(new Uint8Array(wrappedPrivate)),
                                salt: bytesToWebsafeBase64(new Uint8Array(salt.buffer)),
                                rounds: rounds,
                                iv: bytesToWebsafeBase64(new Uint8Array(iv.buffer))
                            }
                        });
                    });
                });
        });
    }

    /**
     * Imports client-side keys from an external key pair object.
     * @param {ExternalKeyPair} keyPair The external key pair object
     *                                  with instructions for unwrapping.
     * @param {Uint8Array} password Password used to derive AES key for
     *                              unwrapping the private key. Wiped from
     *                              memory immediately following usage.
     * @returns A promise which either fulfills upon successfully importing
     *          the key pair, or fails due to an incorrect password or a
     *          a flaw in the external key pair object.
     */
    importKey(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<void> {
        let wrappedPrivate: Uint8Array = websafeBase64ToBytes(keyPair.wrappedPrivateKey);

        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then((derivationKey: CryptoKey) => {
            password.fill(0, 0, password.length);
            
            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: websafeBase64ToBytes(keyPair.salt),
                iterations: keyPair.rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                    name: 'AES-GCM',
                    length: 256
                }, false, ['unwrapKey']).then((aesKey: CryptoKey) => {
                    let iv: ArrayBuffer = websafeBase64ToBytes(keyPair.iv).buffer;
                    return crypto.subtle.unwrapKey('jwk', wrappedPrivate, aesKey, {
                        name: 'AES-GCM',
                        iv: iv, // not included in typings, so cast to 'any'
                        additionalData: iv
                    } as any, {
                        name: 'ECDH',
                        namedCurve: 'P-256' // not included in typings, so cast to 'any'
                    } as any, false, ['deriveKey']).then(unwrappedPrivate => {
                        return crypto.subtle.importKey('raw', websafeBase64ToBytes(keyPair.publicKey), {
                            name: 'ECDH',
                            namedCurve: 'P-256'
                        }, true, []).then(publicKey => {
                            this.clientPrivate = unwrappedPrivate;
                            this.clientPublic = publicKey;

                            return;
                        });
                    });
                });
        });
    }

    constructor() {
        this.clientPrivate = undefined;
        this.serverPublic = undefined;
    }

}