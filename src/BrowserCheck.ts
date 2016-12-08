/**
 * This class implements browser functionality checks for determining
 * whether the default library will work or the shim must be used.
 * 
 * @author Alin Dobra
 * @version 11/9/16
 * @copyright Tera Insights, LLC
 */

export var noECDH = false;

type Algorithm = {
    name?: string,
    namedCurve?: string
}

if (!Uint8Array.from) {
    Uint8Array.from = function (arg) { return new Uint8Array(arg); }
}

// Fix for Safari
if (window.crypto && !window.crypto.subtle && (<any>window).crypto.webkitSubtle) {
    (<any>window).crypto.subtle = (<any>window).crypto.webkitSubtle;
}

// Fix for IE and Edge
if (!window.crypto && (<any>window).msCrypto) {
    (<any>window).crypto = (<any>window).msCrypto;
}

/** Detect if  we are missing the ECDH functionality */
function detectECDH(resolve, reject) {
    function failECDH() {
        noECDH = true;
        console.log("no ECDH support in crypto.subtle. Using shim.");
        reject()
    };

    try {
        window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256",
            },
            true,
            ["deriveKey", "deriveBits"]
        ).then(function (key: CryptoKeyPair) {
            return crypto.subtle.exportKey("jwk", key.privateKey)
                .then(function (keyO: any) {
                    if (keyO.kty !== "EC" || keyO.crv !== "P-256" || !keyO.x || !keyO.y) {
                        failECDH();
                    } else {
                        console.log("crypto.subtle supports ECDH");
                        resolve();
                    }
                });
        }, function (err) {
            failECDH();
        });
    } catch (e) {
        failECDH();
    }
}

export var ensureECDH = new Promise(function (resolve, reject) {
    detectECDH(resolve, reject);
});

var readyPromise = new Promise(function (resolve, reject) {
    // resolve on both paths, sets noECDH if shim needed
    detectECDH(resolve, resolve);
});

export function ready(cb?: (value: {}) => {}) {
    if (cb) {
        readyPromise.then(cb);
    }
    return readyPromise;
}