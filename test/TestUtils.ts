/**
 * This file contains convenience methods for communication with the test server.
 * 
 * @author Sam Claus
 * @version 1/2/17
 * @copyright Tera Insights, LLC
 */

import $ = require('jquery');

interface AuthenticationMessage {
    hmac: string; // base64URL-encoded hmac secret for @msg
    msg: string; // utf-8 message (nothing fancy here)
    key: string; // base64URL-encoded public key
}

interface Secret {
    secret: string; // base64URL-encoded ECDH secret
    key: string; // base64URL-encoded public key
}

const testServerDomain = 'http://localhost:8080/';

export function getServerKey(): Promise<string> {
    return new Promise<string>((succeed, fail) => {
        $.get(testServerDomain + 'key', (key: string, textStatus: string, jqXHR: JQueryXHR) => {
            succeed(key);
        }).fail(() => {
            throw new Error('Couldn\'t connect to server.');
        });
    });
}

export function authenticate(message: AuthenticationMessage): Promise<void> {
    return new Promise<void>((succeed, fail) => {
        $.post(testServerDomain + 'message', message, (reply: string, textStatus: string, jqXHR: JQueryXHR) => {
            if (jqXHR.status == 200) {
                succeed();
            } else {
                throw new Error(reply);
            }
        }).fail(() => {
            throw new Error('Couldn\'t connect to server.');
        });
    });
}

export function testSecret(secret: Secret): Promise<void> {
    return new Promise<void>((succeed, fail) => {
        $.post(testServerDomain + 'ecdh', secret, (reply: string, textStatus: string, jqXHR: JQueryXHR) => {
            if (jqXHR.status == 200) {
                succeed();
            } else {
                throw new Error(reply);
            }
        }).fail(() => {
            throw new Error('Couldn\'t connect to server.');
        });
    });
}