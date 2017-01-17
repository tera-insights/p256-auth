import { Encoding } from './Converters';
import { ExternalKeyPair } from './Crypto';
export declare const serverKeyError: Error;
export declare class Authenticator {
    private clientPrivate;
    private clientPublic;
    private serverPublic;
    generateKeyPair(): PromiseLike<void>;
    importServerKey(serverKey: string): PromiseLike<void>;
    computeHMAC(message: Uint8Array | string, encoding?: Encoding): PromiseLike<string>;
    getPublic(): PromiseLike<string>;
    exportKey(password: Uint8Array): PromiseLike<ExternalKeyPair>;
    importKey(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<void>;
    constructor();
}
