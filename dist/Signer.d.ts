import { Encoding } from './Converters';
import { ExternalKeyPair } from './Crypto';
export declare class Signer {
    private publicKey;
    private privateKey;
    generateKeyPair(): PromiseLike<void>;
    sign(message: string | Uint8Array, encoding?: Encoding): PromiseLike<string>;
    getPublic(): PromiseLike<string>;
    exportKey(password: Uint8Array): PromiseLike<ExternalKeyPair>;
    importKey(keyPair: ExternalKeyPair, password: Uint8Array): PromiseLike<void>;
}
