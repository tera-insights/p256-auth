import { Converters, bytesToWebsafeBase64, websafeBase64ToBytes, Encoding, decodeString } from './Converters';
import { Crypto, ExternalKeyPair, InternalKeyPair } from './Crypto';

export const serverKeyError = new Error('Server public key doesn\'t conform to NIST P-256 curve. If the server uses OpenSSL, ' +
    'the algorithm should be prefixed with "p" or "prime", indicate a size of 256 bits, and be suffixed' +
    'with "v1" or lack a suffix altogether.');

/**
 * Stores session keys and generates HMAC messages
 * using them in ECDH.
 * 
 * @author Sam Claus
 * @version 1/17/17
 * @copyright Tera Insights, LLC
 */
export class Authenticator {

    private clientPrivate: CryptoKey;
    private clientPublic: CryptoKey;
    private serverPublic: CryptoKey;

    /**
     * Generates a new ECDH key pair for the object. Must be
     * called before computing an HMAC, unless a keypair is
     * imported.
     * @returns A promise fulfilling when key pair generation
     *          is finished.
     */
    generateKeyPair(): PromiseLike<void> {
        return Crypto.generateKeys('ECDH').then(keyPair => {
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
            }, () => { throw serverKeyError; });
    }

    /**
     * Computes an HMAC for the given message, using the server
     * and client keys to generate a secret and then hashing it
     * with the message. Results in an error if the Authenticator
     * object hasn't been fed a server public key and generated or
     * imported a client-side key pair.
     * @param {Uint8Array} message Message to sign.
     * @param {string} encoding If @message is a string, the encoding
     *                          to decode it to bytes with.
     * @returns A promise which either fulfills with an HMAC
     *          signature, or fails because a server key and/or client
     *          key pair were never provided.
     */
    computeHMAC(message: Uint8Array | string, encoding?: Encoding): PromiseLike<string> {
        let msgBytes: Uint8Array = message instanceof Uint8Array ? message : decodeString(message, encoding);

        return crypto.subtle.deriveKey({
            name: 'ECDH',
            namedCurve: 'P-256',
            public: this.serverPublic
        } as any, this.clientPrivate, {
                name: 'HMAC',
                hash: 'SHA-256',
                length: 256
            }, false, ['sign']).then(secret => {
                return crypto.subtle.sign({
                    name: 'HMAC'
                } as any, secret, msgBytes).then(signedMessage => {
                    return bytesToWebsafeBase64(new Uint8Array(signedMessage));
                });
            });
    }

    /**
     * Exports the [04 + x + y] public key, encoded to base64URL,
     * for use server-side.
     * @returns A promise which either fulfills with the base64URL-encoded
     *          public key, or fails because no client key pair was attained.
     */
    getPublic(): PromiseLike<string> {
        return Crypto.exportPublic(this.clientPublic);
    }

    /**
     * Exports the client key pair, wrapping the private key using
     * an AES key derived with the given password, random salt, and a
     * random number of rounds of SHA-256.
     * @param {Uint8Array} password Password used to derive AES key
     *                              for wrapping. Wiped from memory
     *                              immediately following usage.
     * @returns A promise which either fulfills with an external key
     *          pair, or fails because a bad password was provided or
     *          no keypair was generated.
     */
    exportKey(password: Uint8Array): PromiseLike<ExternalKeyPair> {
        return Crypto.exportKeyPair(this.clientPublic, this.clientPrivate, 'ECDH', password).then(extKey => {
            return extKey;
        });
    }

    /**
     * Imports client-side keys from an external key pair object.
     * @param {ExternalKeyPair} keyPair The external key pair.
     * @param {Uint8Array} password Password used to derive AES key for
     *                              unwrapping the private key. Wiped from
     *                              memory immediately following usage.
     * @returns A promise which either fulfills upon successfully importing
     *          the key pair, or fails due to either an incorrect password
     *          or the external key pair was not a valid ECDH representation.
     */
    importKey(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<void> {
        return Crypto.importKeyPair(keyPair, password).then(intKey => {
            this.clientPublic = intKey.pubKey;
            this.clientPrivate = intKey.privKey;
            return;
        });
    }

    constructor() {
        this.clientPrivate = undefined;
        this.serverPublic = undefined;
    }

}