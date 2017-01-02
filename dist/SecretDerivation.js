"use strict";
const Converters_1 = require("./Converters");
const Authenticator_1 = require("./Authenticator");
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
//# sourceMappingURL=SecretDerivation.js.map