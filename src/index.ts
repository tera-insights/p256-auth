/**
 * Library entry point. Throws an error if SubtleCrypto isn't supported.
 * 
 * @author Sam Claus
 * @version 12/8/16
 * @copyright Tera Insights, LLC
 */

import { noECDH } from './BrowserCheck';
import { Authenticator } from './Authenticator'
import { ECDHResult, deriveSecret } from './SecretDerivation';

export function createAuthenticator(): Authenticator {
    if (noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    } else {
        return new Authenticator();
    }
}

export function deriveHMACSecret(serverPublic: string): PromiseLike<ECDHResult> {
    if (noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    } else {
        return deriveSecret(serverPublic);
    }
}