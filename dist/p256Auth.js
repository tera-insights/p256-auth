var p256-auth =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.l = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// identity function for calling harmory imports with the correct context
/******/ 	__webpack_require__.i = function(value) { return value; };

/******/ 	// define getter function for harmory exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		Object.defineProperty(exports, name, {
/******/ 			configurable: false,
/******/ 			enumerable: true,
/******/ 			get: getter
/******/ 		});
/******/ 	};

/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};

/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 4);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

"use strict";
"use strict";
const Converters_1 = __webpack_require__(1);
exports.serverKeyError = new Error('Server public key doesn\'t conform to NIST P-256 curve. If the server uses OpenSSL, ' +
    'the algorithm should be prefixed with "p" or "prime", indicate a size of 256 bits, and be suffixed' +
    'with "v1" or lack a suffix altogether.');
class Authenticator {
    generateKeyPair() {
        return crypto.subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, ['deriveKey']).then(keyPair => {
            this.clientPrivate = keyPair.privateKey;
            this.clientPublic = keyPair.publicKey;
            return;
        });
    }
    importServerKey(serverKey) {
        let serverKeyRaw = Converters_1.websafeBase64ToBytes(serverKey);
        return crypto.subtle.importKey('jwk', {
            kty: 'EC',
            crv: 'P-256',
            x: Converters_1.bytesToWebsafeBase64(serverKeyRaw.slice(1, 33)),
            y: Converters_1.bytesToWebsafeBase64(serverKeyRaw.slice(33, 65)),
            ext: false
        }, {
            name: 'ECDH',
            namedCurve: 'P-256'
        }, false, []).then(serverPubKey => {
            this.serverPublic = serverPubKey;
            return;
        }, () => { throw exports.serverKeyError; });
    }
    computeHMAC(message, encoding) {
        let msgBytes = message instanceof Uint8Array ? message : undefined;
        if (!msgBytes) {
            switch (encoding) {
                case 'utf-8':
                    msgBytes = new TextEncoder().encode(message);
                    break;
                case 'hex':
                    msgBytes = Converters_1.Converters.hexToBytes(message);
                    break;
                case 'base64':
                    msgBytes = Converters_1.Converters.base64ToUint8Array(message);
                    break;
                case 'base64URL':
                    msgBytes = Converters_1.websafeBase64ToBytes(message);
                    break;
                default:
                    throw new Error('Not a valid encoding!');
            }
        }
        return crypto.subtle.deriveKey({
            name: 'ECDH',
            namedCurve: 'P-256',
            public: this.serverPublic
        }, this.clientPrivate, {
            name: 'HMAC',
            hash: 'SHA-256',
            length: 256
        }, false, ['sign']).then(secret => {
            return crypto.subtle.sign({
                name: 'HMAC'
            }, secret, msgBytes).then(signedMessage => {
                return Converters_1.bytesToWebsafeBase64(new Uint8Array(signedMessage));
            });
        });
    }
    getPublic() {
        return crypto.subtle.exportKey('raw', this.clientPublic)
            .then(rawPublic => {
            return Converters_1.bytesToWebsafeBase64(new Uint8Array(rawPublic));
        });
    }
    exportKey(password) {
        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then(derivationKey => {
            password.fill(0, 0, password.length);
            let salt = crypto.getRandomValues(new Uint8Array(16));
            let rounds = 10000 * (0.9 + (Math.random() * 0.2));
            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: salt,
                iterations: rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                name: 'AES-GCM',
                length: 256
            }, false, ['wrapKey']).then(aesKey => {
                let iv = crypto.getRandomValues(new Uint8Array(12));
                return crypto.subtle.wrapKey('jwk', this.clientPrivate, aesKey, {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: iv
                }).then(wrappedPrivate => {
                    return this.getPublic().then(extPublic => {
                        return {
                            publicKey: extPublic,
                            wrappedPrivateKey: Converters_1.bytesToWebsafeBase64(new Uint8Array(wrappedPrivate)),
                            salt: Converters_1.bytesToWebsafeBase64(new Uint8Array(salt.buffer)),
                            rounds: rounds,
                            iv: Converters_1.bytesToWebsafeBase64(new Uint8Array(iv.buffer))
                        };
                    });
                });
            });
        });
    }
    importKey(keyPair, password) {
        let wrappedPrivate = Converters_1.websafeBase64ToBytes(keyPair.wrappedPrivateKey);
        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then(derivationKey => {
            password.fill(0, 0, password.length);
            return crypto.subtle.deriveKey({
                name: 'PBKDF2',
                salt: Converters_1.websafeBase64ToBytes(keyPair.salt),
                iterations: keyPair.rounds,
                hash: { name: 'SHA-256' }
            }, derivationKey, {
                name: 'AES-GCM',
                length: 256
            }, false, ['unwrapKey']).then(aesKey => {
                let iv = Converters_1.websafeBase64ToBytes(keyPair.iv).buffer;
                return crypto.subtle.unwrapKey('jwk', wrappedPrivate, aesKey, {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: iv
                }, {
                    name: 'ECDH',
                    namedCurve: 'P-256'
                }, false, ['deriveKey']).then(unwrappedPrivate => {
                    return crypto.subtle.importKey('raw', Converters_1.websafeBase64ToBytes(keyPair.publicKey), {
                        name: 'ECDH',
                        namedCurve: 'P-256'
                    }, true, []).then(publicKey => {
                        this.clientPrivate = unwrappedPrivate;
                        this.clientPublic = publicKey;
                        return;
                    });
                }, () => { throw new Error('User provided incorrect password!'); });
            });
        });
    }
    constructor() {
        this.clientPrivate = undefined;
        this.serverPublic = undefined;
    }
}
exports.Authenticator = Authenticator;


/***/ },
/* 1 */
/***/ function(module, exports) {

"use strict";
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


/***/ },
/* 2 */
/***/ function(module, exports) {

"use strict";
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


/***/ },
/* 3 */
/***/ function(module, exports, __webpack_require__) {

"use strict";
"use strict";
const Converters_1 = __webpack_require__(1);
const Authenticator_1 = __webpack_require__(0);
function deriveSecret(serverPublic) {
    let rawServerPublic = Converters_1.websafeBase64ToBytes(serverPublic);
    return crypto.subtle.importKey('jwk', {
        kty: 'EC',
        crv: 'P-256',
        x: Converters_1.bytesToWebsafeBase64(rawServerPublic.slice(1, 33)),
        y: Converters_1.bytesToWebsafeBase64(rawServerPublic.slice(33, 65)),
        ext: false
    }, {
        name: 'ECDH',
        namedCurve: 'P-256'
    }, false, []).then(serverKey => {
        return crypto.subtle.generateKey({
            name: 'ECDH',
            namedCurve: 'P-256'
        }, true, ['deriveKey']).then(keyPair => {
            return crypto.subtle.deriveKey({
                name: 'ECDH',
                namedCurve: 'P-256',
                public: serverKey
            }, keyPair.privateKey, {
                name: 'HMAC',
                hash: 'SHA-256',
                length: 256
            }, true, ['sign']).then(secret => {
                return Promise.all([
                    crypto.subtle.exportKey('raw', secret),
                    crypto.subtle.exportKey('jwk', keyPair.privateKey)
                ]).then(extKeys => {
                    let rawPubKey = new Uint8Array(65);
                    rawPubKey.set([0x04], 0);
                    rawPubKey.set(Converters_1.websafeBase64ToBytes(extKeys[1].x), 1);
                    rawPubKey.set(Converters_1.websafeBase64ToBytes(extKeys[1].y), 33);
                    return {
                        secret: Converters_1.bytesToWebsafeBase64(new Uint8Array(extKeys[0])),
                        pubKey: Converters_1.bytesToWebsafeBase64(rawPubKey),
                        privKey: extKeys[1].d
                    };
                });
            });
        });
    }, error => {
        throw Authenticator_1.serverKeyError;
    });
}
exports.deriveSecret = deriveSecret;


/***/ },
/* 4 */
/***/ function(module, exports, __webpack_require__) {

"use strict";
"use strict";
const BrowserCheck_1 = __webpack_require__(2);
const Authenticator_1 = __webpack_require__(0);
const SecretDerivation_1 = __webpack_require__(3);
function createAuthenticator() {
    if (BrowserCheck_1.noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    }
    else {
        return new Authenticator_1.Authenticator();
    }
}
exports.createAuthenticator = createAuthenticator;
function deriveHMACSecret(serverPublic) {
    if (BrowserCheck_1.noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    }
    else {
        return SecretDerivation_1.deriveSecret(serverPublic);
    }
}
exports.deriveHMACSecret = deriveHMACSecret;


/***/ }
/******/ ]);