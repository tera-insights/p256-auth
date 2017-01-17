import { Authenticator } from './Authenticator';
import { ECDHResult } from './SecretDerivation';
export declare function createAuthenticator(): Authenticator;
export declare function deriveHMACSecret(serverPublic: string): PromiseLike<ECDHResult>;
