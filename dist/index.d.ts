import { Authenticator } from './Authenticator';
import { Signer } from './Signer';
import { ECDHResult } from './SecretDerivation';
export declare function createAuthenticator(): Authenticator;
export declare function createSigner(): Signer;
export declare function deriveHMACSecret(serverPublic: string): PromiseLike<ECDHResult>;
