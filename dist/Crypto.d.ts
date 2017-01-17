export interface ExternalKeyPair {
    algorithm: string;
    publicKey: string;
    wrappedPrivateKey: string;
    salt: string;
    rounds: number;
    iv: string;
}
export interface InternalKeyPair {
    pubKey: CryptoKey;
    privKey: CryptoKey;
}
export declare class Crypto {
    static generateKeys(algorithm: string): PromiseLike<CryptoKeyPair>;
    static exportKeyPair(pubKey: CryptoKey, privKey: CryptoKey, algorithm: string, password: Uint8Array): PromiseLike<ExternalKeyPair>;
    static importKeyPair(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<InternalKeyPair>;
    static exportPublic(pubKey: CryptoKey): PromiseLike<string>;
}
