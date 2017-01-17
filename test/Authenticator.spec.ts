/**
 * Tests for the Authenticator functionality.
 * 
 * @author Sam Claus
 * @version 1/17/17
 * @copyright Tera Insights
 */

import { Authenticator } from '../src/Authenticator';
import { getServerKey, authenticate, verifySignature } from './TestUtils'
import { websafeBase64ToBytes } from '../src/Converters';
import mocha = require('mocha');

declare class TextEncoder {
    constructor()
    encode(str: string): Uint8Array
}

describe('Authenticator', () => {
    it('should produce a valid authentication message', () => {
        const authenticator = new Authenticator();
        const message = 'A message to the server.';

        return getServerKey().then(serverKey => {
            return authenticator.generateKeyPair().then(() => {
                return authenticator.importServerKey(serverKey).then(() => {
                    return authenticator.computeHMAC(message, 'utf-8').then(hmac => {
                        return authenticator.getPublic().then(clientKey => {
                            return authenticate({
                                hmac: hmac,
                                msg: message,
                                key: clientKey
                            });
                        });
                    });
                });
            });
        });
    });
    it('should generate a key pair and export it, then import it and produce a valid authentication message', () => {
        let authenticator = new Authenticator();
        const message = 'A message to the server.';

        return getServerKey().then(serverKey => {
            return authenticator.generateKeyPair().then(() => {
                return authenticator.exportKey(new Uint8Array([1, 0, 3, 7, 9, 8, 2, 2, 2])).then(extKey => {
                    authenticator = new Authenticator();
                    return authenticator.importKey(extKey, new Uint8Array([1, 0, 3, 7, 9, 8, 2, 2, 2])).then(() => {
                        return authenticator.importServerKey(serverKey).then(() => {
                            return authenticator.computeHMAC(message, 'utf-8').then(hmac => {
                                return authenticator.getPublic().then(clientKey => {
                                    return authenticate({
                                        hmac: hmac,
                                        msg: message,
                                        key: clientKey
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});