"use strict";
exports.noECDH = false;
if (!Uint8Array.from) {
    Uint8Array.from = function (arg) { return new Uint8Array(arg); };
}
if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
    window.crypto.subtle = window.crypto.webkitSubtle;
}
if (!window.crypto && window.msCrypto) {
    window.crypto = window.msCrypto;
}
function detectECDH(resolve, reject) {
    function failECDH() {
        exports.noECDH = true;
        console.log("no ECDH support in crypto.subtle. Using shim.");
        reject();
    }
    ;
    try {
        window.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-256",
        }, true, ["deriveKey", "deriveBits"]).then(function (key) {
            return crypto.subtle.exportKey("jwk", key.privateKey)
                .then(function (keyO) {
                if (keyO.kty !== "EC" || keyO.crv !== "P-256" || !keyO.x || !keyO.y) {
                    failECDH();
                }
                else {
                    console.log("crypto.subtle supports ECDH");
                    resolve();
                }
            });
        }, function (err) {
            failECDH();
        });
    }
    catch (e) {
        failECDH();
    }
}
exports.ensureECDH = new Promise(function (resolve, reject) {
    detectECDH(resolve, reject);
});
var readyPromise = new Promise(function (resolve, reject) {
    detectECDH(resolve, resolve);
});
function ready(cb) {
    if (cb) {
        readyPromise.then(cb);
    }
    return readyPromise;
}
exports.ready = ready;
//# sourceMappingURL=BrowserCheck.js.map