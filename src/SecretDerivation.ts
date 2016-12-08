/**
 * Standalone functionality for producing a secret for HMAC use.
 * 
 * @author Sam Claus
 * @version 12/8/16
 * @copyright Tera Insights, LLC
 */

import { bytesToWebsafeBase64, websafeBase64ToBytes } from './Converters';

export interface ECDHResult {
    secret: string; // ECDH Secret (websafe-base64)
    pubKey: string; // ECDH public (websafe-base64 of 65 bytes)
    privKey: string; // ECDH private (websafe-base64 of 32 bytes)
}

/**
 * Given a server public key, generates a keypair and computes an ECDH secret.
 * @param {string} serverPublic Websafe-base64 server public key.
 * @returns A promise returning an ECDHResult containing the base64URL-encoded
 *          ECDH secret for use with HMAC, as well as the base64URL-encoded
 *          private and public keys generated.
 */
export function deriveSecret(serverPublic: string): PromiseLike<ECDHResult> {
    let rawServerPublic: Uint8Array = websafeBase64ToBytes(serverPublic);

    return crypto.subtle.importKey('jwk', {
        kty: 'EC',
        crv: 'P-256',
        x: bytesToWebsafeBase64(rawServerPublic.slice(1, 33)),
        y: bytesToWebsafeBase64(rawServerPublic.slice(33, 65)),
        ext: false
    }, {
            name: 'ECDH',
            namedCurve: 'P-256'
        }, false, []).then(serverKey => {
            return crypto.subtle.generateKey({
                name: 'ECDH',
                namedCurve: 'P-256'
            }, true, ['deriveKey']).then(keyPair => {
                return crypto.subtle.deriveKey({
                    name: 'ECDH',
                    namedCurve: 'P-256',
                    public: serverKey
                } as any, keyPair.privateKey, {
                        name: 'HMAC',
                        length: 256
                    }, true, []).then(secret => {
                        return Promise.all([
                            crypto.subtle.exportKey('raw', secret),
                            crypto.subtle.exportKey('jwk', keyPair.privateKey)
                        ]).then(extKeys => {
                            // Construct public key
                            let rawPubKey: Uint8Array = new Uint8Array(65);
                            rawPubKey.set([0x04], 0);
                            rawPubKey.set(websafeBase64ToBytes(extKeys[1].x), 1);
                            rawPubKey.set(websafeBase64ToBytes(extKeys[1].y), 33);

                            return {
                                secret: bytesToWebsafeBase64(new Uint8Array(extKeys[0])),
                                pubKey: bytesToWebsafeBase64(rawPubKey),
                                privKey: extKeys[1].d
                            };
                        });
                    });
            });
        });
}