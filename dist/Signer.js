"use strict";
const Converters_1 = require("./Converters");
const Crypto_1 = require("./Crypto");
class Signer {
    generateKeyPair() {
        return Crypto_1.Crypto.generateKeys('ECDSA').then(keyPair => {
            this.privateKey = keyPair.privateKey;
            this.publicKey = keyPair.publicKey;
            return;
        });
    }
    sign(message, encoding) {
        let msgBytes = message instanceof Uint8Array ? message : Converters_1.decodeString(message, encoding);
        return crypto.subtle.sign({
            name: 'ECDSA',
            hash: 'SHA-256'
        }, this.privateKey, msgBytes).then(signature => {
            return Converters_1.bytesToWebsafeBase64(new Uint8Array(signature));
        });
    }
    getPublic() {
        return Crypto_1.Crypto.exportPublic(this.publicKey);
    }
    exportKey(password) {
        return Crypto_1.Crypto.exportKeyPair(this.publicKey, this.privateKey, 'ECDSA', password).then(extKey => {
            return extKey;
        });
    }
    importKey(keyPair, password) {
        return Crypto_1.Crypto.importKeyPair(keyPair, password).then(intKey => {
            this.privateKey = intKey.privKey;
            this.publicKey = intKey.pubKey;
            return;
        });
    }
}
exports.Signer = Signer;
//# sourceMappingURL=Signer.js.map