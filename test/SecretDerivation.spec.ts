/**
 * Tests for the HMAC secret derivation functionality.
 * 
 * @author Sam Claus
 * @version 1/2/17
 * @copyright Tera Insights
 */

import { ECDHResult, deriveSecret } from '../src/SecretDerivation';
import { getServerKey, testSecret } from './TestUtils';
import mocha = require('mocha');

describe('SecretDerivation', () => {
    it('should generate a key pair and compute a valid ECDH secret, given a public key', () => {
        return getServerKey().then(serverKey => {
            return deriveSecret(serverKey).then(result => {
                return testSecret({
                    secret: result.secret,
                    key: result.pubKey
                });
            });
        });
    });
});