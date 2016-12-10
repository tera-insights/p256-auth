/// <reference path="../typings/index.d.ts" />

/**
 * This file contains convenience methods for communication with the test server.
 * 
 * @author Sam Claus
 * @version 12/9/16
 * @copyright Tera Insights, LLC
 */

import * as $ from 'jquery';

export interface AuthenticationMessage {
    hmac: string; // websafe-base64-encoded hmac secret for @msg
    msg: string; // utf-8 message (nothing fancy here)
    key: string; // websafe-base64-encoded public key
}

export let testServerDomain = 'http://localhost:8080/';

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