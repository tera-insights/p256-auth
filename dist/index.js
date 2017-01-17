"use strict";
const BrowserCheck_1 = require("./BrowserCheck");
const Authenticator_1 = require("./Authenticator");
const Signer_1 = require("./Signer");
const SecretDerivation_1 = require("./SecretDerivation");
function createAuthenticator() {
    if (BrowserCheck_1.noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    }
    else {
        return new Authenticator_1.Authenticator();
    }
}
exports.createAuthenticator = createAuthenticator;
function createSigner() {
    if (BrowserCheck_1.noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    }
    else {
        return new Signer_1.Signer();
    }
}
exports.createSigner = createSigner;
function deriveHMACSecret(serverPublic) {
    if (BrowserCheck_1.noECDH) {
        throw new Error('No crypto functionality detected! Use Chrome or Firefox.');
    }
    else {
        return SecretDerivation_1.deriveSecret(serverPublic);
    }
}
exports.deriveHMACSecret = deriveHMACSecret;
//# sourceMappingURL=index.js.map