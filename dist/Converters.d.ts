export declare type Encoding = 'utf-8' | 'hex' | 'base64' | 'base64URL';
export declare class Converters {
    static stringToUint8Array(data: string): Uint8Array;
    static Uint8ArrayToString(data: Uint8Array): string;
    static base64ToUint8Array(data: string): Uint8Array;
    static Uint8ArrayToBase64(data: Uint8Array): string;
    static base64ToBase64URL(data: string): string;
    static base64URLToBase64(data: string): string;
    static jwkToString(key: any, pubOnly?: boolean): string;
    static stringToJwk(key: string): any;
    static hexToBytes(hex: string): Uint8Array;
    static bytesToHex(bytes: Uint8Array): string;
}
export declare function bytesToWebsafeBase64(data: Uint8Array): string;
export declare function websafeBase64ToBytes(data: string): Uint8Array;
export declare function decodeString(str: string, encoding?: Encoding): Uint8Array;
