/**
 * Simple express server for testing purposes.
 * 
 * @author Sam Claus
 * @version 12/9/16
 * @copyright Tera Insights, LLC
 */

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');

// Generate server key pair
const ecdh = crypto.createECDH('p256');
const publicKey = ecdh.generateKeys('base64').replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '');

// Parses json from requests
app.use(bodyParser.urlencoded());

// Get the server public key (in websafe-base64)
app.get('/key', function (req, res) {
    res.send(publicKey);
});

// Send the server a test message with hmac authentication, replies with 200 if successful
app.post('/message', function (req, res) {
    const clientHmac = req.body.hmac;
    const msg = req.body.msg;
    const clientKey = req.body.key;

    if (!clientHmac || !msg || !clientKey) {
        res.status(400).send('Bad request--It\'s not you, it\'s the TestUtils. :(');
        return;
    }

    const secret = ecdh.computeSecret(clientKey, 'base64'); // buffer
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(msg);
    const serverHmac = makeWebsafe(hmac.digest('base64'));

    if (clientHmac === serverHmac) {
        res.status(200).send();
    } else {
        res.status(401).send('Authentication failed.');
    }
});

// Converts base64 to websafe-base64
function makeWebsafe (base64) {
    return base64.replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '')
}