export interface ECDHResult {
    secret: string;
    pubKey: string;
    privKey: string;
}
export declare function deriveSecret(serverPublic: string): PromiseLike<ECDHResult>;
