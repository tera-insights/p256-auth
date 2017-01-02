"use strict";
class Converters {
    static stringToUint8Array(data) {
        return Uint8Array.from(Array.prototype.map.call(data, x => { return x.charCodeAt(0); }));
    }
    static Uint8ArrayToString(data) {
        return Array.prototype.map.call(data, x => {
            return String.fromCharCode(x);
        }).join('');
    }
    static base64ToUint8Array(data) {
        var asStr = atob(data);
        return Converters.stringToUint8Array(asStr);
    }
    static Uint8ArrayToBase64(data) {
        return btoa(Converters.Uint8ArrayToString(data));
    }
    static base64ToBase64URL(data) {
        return data.split('=')[0].replace(/\+/g, '-').replace(/\//g, '_');
    }
    static base64URLToBase64(data) {
        var d = data.replace(/\-/g, '+').replace(/\_/g, '/');
        switch (d.length % 4) {
            case 0: break;
            case 2:
                d = d + "==";
                break;
            case 3:
                d = d + "=";
                break;
        }
        return d;
    }
    static jwkToString(key, pubOnly) {
        if (key.kty !== "EC" || key.crv !== "P-256" || !key.x || !key.y)
            throw new Error("Key type not supported");
        if (key.d && !pubOnly)
            return [key.x, key.y, key.d].join('|');
        else
            return [key.x, key.y].join('|');
    }
    static stringToJwk(key) {
        var arr = key.split('|');
        if (arr.length < 2 || arr.length > 3)
            throw new Error("Wrong string key representation");
        var ret = {
            kty: "EC", crv: "P-256", x: arr[0], y: arr[1],
            key_ops: ['deriveKey']
        };
        if (arr[2]) {
            ret.d = arr[2];
        }
        return ret;
    }
    static hexToBytes(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return new Uint8Array(bytes);
    }
    static bytesToHex(bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }
}
exports.Converters = Converters;
function bytesToWebsafeBase64(data) {
    return Converters.base64ToBase64URL(Converters.Uint8ArrayToBase64(data));
}
exports.bytesToWebsafeBase64 = bytesToWebsafeBase64;
function websafeBase64ToBytes(data) {
    return Converters.base64ToUint8Array(Converters.base64URLToBase64(data));
}
exports.websafeBase64ToBytes = websafeBase64ToBytes;
//# sourceMappingURL=Converters.js.map