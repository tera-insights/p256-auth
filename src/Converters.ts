declare class TextEncoder {
    constructor()
    encode(str: string): Uint8Array
}

export type Encoding = 'utf-8' | 'hex' | 'base64' | 'base64URL';

/**
 * Simple binary, hex, and base64 conversion functions.
 * 
 * @author Alin Dobra
 * @version 12/8/16
 * @copyright Tera Insights
 */
export class Converters {

    /**
     * Function to convert strings to binary data
     * 
     * @static
     * @param {string} data
     * @returns {Uint8Array}
     */
    static stringToUint8Array(data: string): Uint8Array {
        return Uint8Array.from(Array.prototype.map.call(data, x => { return x.charCodeAt(0); }))
    }

    /**
     * Function to convert binary data to string 
     * 
     * @static
     * @param {Uint8Array} data
     * @returns {string}
     */
    static Uint8ArrayToString(data: Uint8Array): string {
        return Array.prototype.map.call(data, x => {
            return String.fromCharCode(x);
        }).join('');
    }

    /**
     * Function to convert base64 strings to Uint8Array
     * @data is the string to be converted
     * @returns The raw Uint8Array
     */
    static base64ToUint8Array(data: string): Uint8Array {
        var asStr = atob(data);
        return Converters.stringToUint8Array(asStr);
    }

    /**
     * Function to convert Uint8Array (raw data) to base64
     * @data The Uint8Array to convert
     * @returns The base64 encoded @data as string
     */
    static Uint8ArrayToBase64(data: Uint8Array): string {
        return btoa(Converters.Uint8ArrayToString(data));
    }

    /**
     * Function to convert Base64 for Base64URL 
     * 
     * @static
     * @param {string} data
     * @returns {string}
     */
    static base64ToBase64URL(data: string): string {
        return data.split('=')[0].replace(/\+/g, '-').replace(/\//g, '_');
    }

    /**
     * Counterpart function of the above 
     * 
     * @static
     * @param {string} data
     * @returns {string}
     */
    static base64URLToBase64(data: string): string {
        var d = data.replace(/\-/g, '+').replace(/\_/g, '/');
        switch (d.length % 4) {
            case 0: break; // no padding
            case 2: d = d + "=="; break; // 2 char padding
            case 3: d = d + "="; break; // 1 char padding
        }
        return d;
    }

    /**
     * Function to convert from jwt format to a simpler text format.
     * Works for both private and public keys. a
     * 
     * Note 1: Only works correctly for P-256 
     * Note 2: The string representation of the key is base64_x|base64_y
     * NOte 3: The Base64 encoding used by crypto.subtle is non standard. See:
     * http://self-issued.info/docs/draft-goland-json-web-token-00.html#base64urlnotes
     * 
     * @static
     * @param {*} key The key in jwt format
     * @returns {string} String representation of the key. 
     */
    static jwkToString(key: any, pubOnly?: boolean): string {
        if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y)
            throw new Error("Key type not supported");
        if (key.d && !pubOnly) // private key  
            return [key.x, key.y, key.d].join('|');
        else // public only
            return [key.x, key.y].join('|');
    }

    /**
     * Counterpart of above 
     * 
     * @static
     * @param {string} key
     * @returns {*}
     */
    static stringToJwk(key: string): any {
        var arr = key.split('|');
        if (arr.length < 2 || arr.length > 3)
            throw new Error("Wrong string key representation");
        var ret: any = {
            kty: "EC", crv: "P-256", x: arr[0], y: arr[1],
            key_ops: ['deriveKey']
        }
        if (arr[2]) { // private key
            ret.d = arr[2];
        }
        return ret;
    }

    // Convert a hex string to a byte array
    static hexToBytes(hex: string): Uint8Array {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return new Uint8Array(bytes);
    }

    // Convert a byte array to a hex string
    static bytesToHex(bytes: Uint8Array): string {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }

}

/**
 * Convenience method for converting from a Uint8Array to a websafe-base64 string.
 * @param {Uint8Array} data The data to encode.
 * @returns A websafe-base64 encoding of the data.
 */
export function bytesToWebsafeBase64(data: Uint8Array): string {
    return Converters.base64ToBase64URL(Converters.Uint8ArrayToBase64(data));
}

/**
 * Convenience method for converting from a websafe-base64 string to a Uint8Array.
 * @param {string} data A websafe-base64 string.
 * @returns The raw bytes encoded in the string.
 */
export function websafeBase64ToBytes(data: string): Uint8Array {
    return Converters.base64ToUint8Array(Converters.base64URLToBase64(data));
}

/**
 * Given a string and an encoding, breaks the string into raw bytes.
 * @param {string} str The string to decode.
 * @param {Encoding} encoding The encoding to decode with, utf-8 by
 *                            default.
 * @returns A Uint8Array filled with the decoded bytes.
 */
export function decodeString(str: string, encoding?: Encoding): Uint8Array {
    let bytes: Uint8Array;

    if(!encoding) {
        encoding = 'utf-8';
    }

    switch (encoding) {
        case 'utf-8':
            bytes = new TextEncoder().encode(str as string);
            break;
        case 'hex':
            bytes = Converters.hexToBytes(str as string);
            break;
        case 'base64':
            bytes = Converters.base64ToUint8Array(str as string);
            break;
        case 'base64URL':
            bytes = websafeBase64ToBytes(str as string);
            break;
        default:
            throw new Error('Not a valid encoding!');
    }

    return bytes;
}