export declare const serverKeyError: Error;
export interface ExternalKeyPair {
    publicKey: string;
    wrappedPrivateKey: string;
    salt: string;
    rounds: number;
    iv: string;
}
export declare type Encoding = 'utf-8' | 'hex' | 'base64' | 'base64URL';
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
