"use strict";
const Converters_1 = require("./Converters");
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
//# sourceMappingURL=Authenticator.js.map