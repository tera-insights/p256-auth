"use strict";
const Converters_1 = require("./Converters");
const Crypto_1 = require("./Crypto");
exports.serverKeyError = new Error('Server public key doesn\'t conform to NIST P-256 curve. If the server uses OpenSSL, ' +
    'the algorithm should be prefixed with "p" or "prime", indicate a size of 256 bits, and be suffixed' +
    'with "v1" or lack a suffix altogether.');
class Authenticator {
    generateKeyPair() {
        return Crypto_1.Crypto.generateKeys('ECDH').then(keyPair => {
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
        let msgBytes = message instanceof Uint8Array ? message : Converters_1.decodeString(message, encoding);
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
        return Crypto_1.Crypto.exportPublic(this.clientPublic);
    }
    exportKey(password) {
        return Crypto_1.Crypto.exportKeyPair(this.clientPublic, this.clientPrivate, 'ECDH', password).then(extKey => {
            return extKey;
        });
    }
    importKey(keyPair, password) {
        return Crypto_1.Crypto.importKeyPair(keyPair, password).then(intKey => {
            this.clientPublic = intKey.pubKey;
            this.clientPrivate = intKey.privKey;
            return;
        });
    }
    constructor() {
        this.clientPrivate = undefined;
        this.serverPublic = undefined;
    }
}
exports.Authenticator = Authenticator;
//# sourceMappingURL=Authenticator.js.map