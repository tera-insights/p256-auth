# Welcome to P256-Auth!

*P256-Auth* is a simple library for **handling ECDH keys** and using them to **produce HMAC secrets**.
Alternatively, the library can go all the way and compute the HMAC of a message using an internally
derived secret. All you have to do is feed it your server's public key and tell it to generate or import
a key pair. All operations are done strictly within the bounds of SubtleCrypto so that **unwrapped private
keys never touch the javascript**.

## Getting Started

The *P256-Auth* API is very straightforward. Just install it using `npm install p256-auth`, then you can begin.
Keep in mind the library only works with two key formats: websafe-base64-encoded 65-byte public keys, and it's own
proprietary external key format, which is used for exporting and importing key pairs between Authenticator instances--
and they can be safely saved to file and used later on.

```
// General usage
var p256Auth = require('p256-auth');
var serverKey = getKeyFromYourServer(); // server-side public ECDH key

var authenticator = new p256Auth.Authenticator();

authenticator.generateKeyPair();
authenticator.importServerKey(serverKey);
var clientKey = authenticator.getPublic(); // client-side public ECDH key
sendPublicKeyToServer(clientKey);

var message = produceAMessageForYourServer(); // must be Uint8Array
var hmacSecret = authenticator.computeHMAC(message); // websafe-base64 string
sendMessageToYourServer(hmacSecret, message);

// Exporting and importing keys
var externalKeyPair = authenticator.exportKey(somePasswordToEncryptWith); // password must be Uint8Array

var authenticator2 = new p256Auth.Authenticator();
authenticator2.importKey(externalKeyPair, samePasswordNewInstance); // previous password instance was wiped for security
authenticator2.importServerKey(serverKey);

var sameSecret = authenticator2.computeHMAC(message);
sendMessageToYourServer(sameSecret, message);
```

## Testing

Extensive tests are provided to make sure *P256-Auth* runs properly on your platform. Because the library is
security-oriented, your platform must implement *SubtleCrypto*. At the time of development, only Chrome, Firefox,
and platforms built on the V8 engine (e.g. Opera and Node) implement enough of *SubtleCrypto* to run the library.
Before running tests, some setup needs to happen. This guide assumes you already have Node installed.

```
// any of these may require 'sudo'
npm install karma-cli -g
npm install webpack -g
npm install typings -g

// from the root directory of the project
typings install
npm install
```

Once you've installed the necessary tools, you must first start the test server, then run the tests themselves
with *Karma*.

```
// from the root directory of the project (starts the test server)
npm start

// from another terminal, also in the project root
npm test
```