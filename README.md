# Welcome to P256-Auth!

*P256-Auth* is a simple library for **handling ECDH keys** and using them to **produce HMAC secrets** in the browser.
Alternatively, the library can go all the way and compute the HMAC of a message using an internally
derived secret. All you have to do is feed it your server's public key and tell it to generate or import
a key pair. All operations are done strictly within the bounds of SubtleCrypto so that **unwrapped private
keys never touch the javascript**.

## Getting Started

The *P256-Auth* API is very straightforward. Just install it using `npm install p256-auth`, then you can begin.
Keep in mind the library only works with two key formats: base64URL-encoded 65-byte public keys, and it's own
proprietary external key format (JSON), which is used for exporting and importing key pairs between Authenticator instances--and
they can be safely saved to file and used later on. Due to the asynchronous nature of SubtleCrypto, all API calls return promises
except `createAuthenticator()`. See the [wiki]() for full API documentation.

### General Usage
```
var p256Auth = require('p256-auth');
var serverKey = getKeyFromYourServer(); // server-side public ECDH key

var authenticator = p256Auth.createAuthenticator();

authenticator.generateKeyPair().then(() => {
    Promise.all([authenticator.importServerKey(serverKey), authenticator.getPublic()]).then(([undefined, clientKey]) => {
        sendPublicKeyToServer(clientKey);

        var message = produceAMessageForYourServer(); // must be Uint8Array or string
        authenticator.computeHMAC(message).then(hmacSecret => {
            sendMessageToYourServer(hmacSecret, message);
        }); // fulfills with websafe-base64 string
    });
});
```

### Exporting and importing keys

When you export keys, the private undergoes a wrapping process before being exported from the native SubtleCrypto
API, and a `Uint8Array` password must be provided for wrapping. The reason the password is passed as a `Uint8Array`
and not a `string` is because strings are heavily abstracted in Javascript, but the library needs to wipe the
password from memory immediately following use to maximize security, which can only really be achieved with an
`ArrayBuffer` or child type.

```
// Continued from above...
authenticator.exportKey(somePasswordToEncryptWith).then(extKey => { // password must be Uint8Array
    var authenticator2 = p256Auth.createAuthenticator();

    Promise.all([authenticator2.importKey(externalKeyPair, samePasswordNewInstance), authenticator2.importServerKey(serverKey)]).then(() => {
        authenticator2.computeHMAC(message).then(sameSecret => {
            sendMessageToYourServer(sameSecret, message);
        });
    });
});
```

### Signing messages

While *P256-Auth* was primarily designed for HMAC usage, it also contains signing functionality.

```
// Continued from above
authenticator.sign('some message', 'utf-8').then(signature => {
    // do something with the Uint8Array signature
});

authenticator.sign(someRawUint8Array).then(signature => {
    // same deal as before
});
```

### Use with Typescript
*P256-Auth* is packaged with types alongside the Javascript, so NPM and Typescript do the heavy lifting for you. Simply use
`import` in place of `var` when requiring the package, and types will be linked automatically.
```
import p256Auth = require('p256-auth');
```

## Testing

Extensive tests are provided to make sure *P256-Auth* runs properly on your platform. Because the library is
security-oriented, your platform must implement *SubtleCrypto*. At the time of development, only Firefox and
platforms built on the V8 engine (e.g. Chrome and Opera) implement enough of *SubtleCrypto* to run the library.
To run the tests, simply use the NPM scripts included:

1. Start the test server: `npm start`
2. Run the *Karma* tests: `npm test` (in another terminal)