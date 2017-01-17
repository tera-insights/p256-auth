"use strict";
const Converters_1 = require("./Converters");
class Crypto {
    static generateKeys(algorithm) {
        let usage = algorithm === 'ECDH' ? 'deriveKey' : 'sign';
        return crypto.subtle.generateKey({
            name: algorithm,
            namedCurve: 'P-256'
        }, true, [usage]).then(keyPair => {
            return keyPair;
        });
    }
    static exportKeyPair(pubKey, privKey, algorithm, password) {
        return crypto.subtle.importKey('raw', password, {
            name: 'PBKDF2'
        }, false, ['deriveKey']).then(derivationKey => {
            password.fill(0, 0, password.length);
            let salt = crypto.getRandomValues(new Uint8Array(16));
            let rounds = Math.floor(10000 * (0.9 + (Math.random() * 0.2)));
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
                return crypto.subtle.wrapKey('jwk', privKey, aesKey, {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: iv
                }).then(wrappedPrivate => {
                    return crypto.subtle.exportKey('raw', pubKey).then(rawPublic => {
                        return {
                            algorithm: algorithm,
                            publicKey: Converters_1.bytesToWebsafeBase64(new Uint8Array(rawPublic)),
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
    static importKeyPair(keyPair, password) {
        let wrappedPrivate = Converters_1.websafeBase64ToBytes(keyPair.wrappedPrivateKey);
        let usage = keyPair.algorithm === 'ECDH' ? 'deriveKey' : 'sign';
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
                    name: keyPair.algorithm,
                    namedCurve: 'P-256'
                }, false, [usage]).then(unwrappedPrivate => {
                    return crypto.subtle.importKey('raw', Converters_1.websafeBase64ToBytes(keyPair.publicKey), {
                        name: keyPair.algorithm,
                        namedCurve: 'P-256'
                    }, true, []).then(publicKey => {
                        return {
                            pubKey: publicKey,
                            privKey: unwrappedPrivate
                        };
                    });
                }, () => { throw new Error('User provided incorrect password!'); });
            });
        });
    }
    static exportPublic(pubKey) {
        return crypto.subtle.exportKey('raw', pubKey).then(rawPublic => {
            return Converters_1.bytesToWebsafeBase64(new Uint8Array(rawPublic));
        });
    }
}
exports.Crypto = Crypto;
//# sourceMappingURL=Crypto.js.map