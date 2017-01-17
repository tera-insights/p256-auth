/**
 * Tests for the Signer functionality.
 * 
 * @author Sam Claus
 * @version 1/17/17
 * @copyright Tera Insights
 */

import { Authenticator } from '../src/Authenticator';
import { Signer } from '../src/Signer';
import { verifySignature } from './TestUtils'
import { websafeBase64ToBytes, Converters } from '../src/Converters';
import mocha = require('mocha');

declare class TextEncoder {
    constructor()
    encode(str: string): Uint8Array
}

describe('Signer', () => {
    it('should correctly sign a message', () => {
        let signer = new Signer();
        let message = 'Some message.';

        return signer.generateKeyPair().then(() => {
            return Promise.all([signer.sign(message), signer.getPublic()]).then(([signature, pubKey]) => {
                return verifySignature(websafeBase64ToBytes(pubKey), websafeBase64ToBytes(signature),
                    new TextEncoder().encode(message));
            });
        });
    });
    it('should generate a key pair and export it, then import it and correctly sign a message with it', () => {
        let signer = new Signer();
        let message = 'Another message.';

        return signer.generateKeyPair().then(() => {
            return signer.exportKey(new Uint8Array([0, 9, 9, 9, 7, 3])).then(extKey => {
                signer = new Signer();
                return signer.importKey(extKey, new Uint8Array([0, 9, 9, 9, 7, 3])).then(() => {
                    return Promise.all([signer.sign(message), signer.getPublic()]).then(([signature, pubKey]) => {
                        return verifySignature(websafeBase64ToBytes(pubKey), websafeBase64ToBytes(signature),
                            new TextEncoder().encode(message));
                    });
                });
            });
        });
    });
});