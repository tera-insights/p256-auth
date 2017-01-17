import { Encoding, decodeString, websafeBase64ToBytes, bytesToWebsafeBase64 } from './Converters';
import { Crypto, ExternalKeyPair, InternalKeyPair } from './Crypto';

/**
 * This class handles a key pair for use with ECDSA, because SubtleCrypto
 * makes it illegal to use an ECDH pair for ECDSA, so functionality must
 * be separated. Errors will be thrown if an Authenticator-produced external
 * key pair is imported to a Signer.
 * 
 * @author Sam Claus
 * @version 1/17/17
 * @copyright Tera Insights, LLC
 */
export class Signer {

    private publicKey: CryptoKey;
    private privateKey: CryptoKey;

    /**
     * Generates a new ECDSA key pair for the object. Must be
     * called before attempting to sign.
     * @returns A promise fulfilling when key pair generation
     *          is finished.
     */
    generateKeyPair(): PromiseLike<void> {
        return Crypto.generateKeys('ECDSA').then(keyPair => {
            this.privateKey = keyPair.privateKey;
            this.publicKey = keyPair.publicKey;
            return;
        });
    }

    /**
     * Signs a message using a generated or imported private key.
     * @param {string|Uint8Array} message The message to sign.
     * @param {Encoding}          encoding If @message is a string, the
     *                                     encoding to decode it with, 
     *                                     utf-8 by default.
     * @returns A promise which either fulfills with a base64URL-
     *          encoded signature, or fails because a private key was
     *          never attained to sign with.
     */
    sign(message: string | Uint8Array, encoding?: Encoding): PromiseLike<string> {
        let msgBytes: Uint8Array = message instanceof Uint8Array ? message : decodeString(message, encoding);

        return crypto.subtle.sign({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, this.privateKey, msgBytes).then(signature => {
            return bytesToWebsafeBase64(new Uint8Array(signature));
        });
    }

    /**
     * Exports the P-256 ECDSA public key of 65 bytes.
     * @returns base64URL-encoded binary of form:
     *          [04 + x + y].
     */
    getPublic(): PromiseLike<string> {
        return Crypto.exportPublic(this.publicKey);
    }

    /**
     * Exports the signing key pair, wrapping the private key using
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
        return Crypto.exportKeyPair(this.publicKey, this.privateKey, 'ECDSA', password).then(extKey => {
            return extKey;
        });
    }

    /**
     * Import an external ECDSA key pair.
     * @param {ExternalKeyPair} keyPair  The external key pair.
     * @param {Uint8Array}      password Password to unwrap the key.
     * @returns A promise which fulfills when the key has been
     *          successfully imported, or fails because either an
     *          incorrect password was provided or the external key
     *          pair was not a valid ECDSA representation.
     */
    public importKey(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<void> {
        return Crypto.importKeyPair(keyPair, password).then(intKey => {
            this.privateKey = intKey.privKey;
            this.publicKey = intKey.pubKey;
            return;
        });
    }

}