/**
 * Simple express server for testing purposes.
 * 
 * @author Sam Claus
 * @version 1/2/17
 * @copyright Tera Insights, LLC
 */

var express = require('express');
var app = express();
var cors = require('cors');
var bodyParser = require('body-parser');
var crypto = require('crypto');

// Generate server key pair
var ecdh = crypto.createECDH('prime256v1');
var publicKey = ecdh.generateKeys('base64').replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '');

// Parses json from requests
app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));

// Get the server public key (in websafe-base64)
app.get('/key', function (req, res) {
    console.log('Sent key!');
    res.send(publicKey);
});

// Send the server a test message with hmac authentication, replies with 200 if successful
app.post('/message', function (req, res) {
    console.log('Message received!');
    var clientHmac = req.body.hmac;
    var msg = req.body.msg;
    var clientKey = req.body.key;

    if (!clientHmac || !msg || !clientKey) {
        res.status(400).send('Bad request--It\'s not you, it\'s the TestUtils. :(');
        return;
    }

    var secret = ecdh.computeSecret(clientKey, 'base64'); // buffer
    var hmac = crypto.createHmac('sha256', secret);
    hmac.update(msg);
    var serverHmac = makeWebsafe(hmac.digest('base64'));

    if (clientHmac === serverHmac) {
        console.log('Authentication successful!');
        res.status(200).send();
    } else {
        res.status(401).send('Authentication failed.');
    }
});

// Tests client ECDH functionality, replies with 200 if successful
app.post('/ecdh', function (req, res) {
    console.log('Secret received!');
    var clientSecret = req.body.secret;
    var clientKey = req.body.key;

    if (!clientSecret || !clientKey) {
        res.status(400).send('Bad request--It\'s not you, it\'s the TestUtils. :(');
        return;
    }

    var secret = ecdh.computeSecret(clientKey, 'base64');

    if (secret.equals(new Buffer(clientSecret, 'base64'))) {
        console.log('Valid secret!')
        res.status(200).send();
    } else {
        res.status(401).send('Incorrect secret.')
    }
});

app.listen(8080, function () {
    console.log('Listening on 8080!');
});

// Converts base64 to websafe-base64
function makeWebsafe (base64) {
    return base64.replace(/\//g,'_').replace(/\+/g,'-').replace(/=/g, '')
}