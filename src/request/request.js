const TokenIssuer = require('../authentication/tokenissuer');
const request = require('request');

function Request(hostName, tokenSecret) {
    this._hostName = hostName;
    if(tokenSecret) {
        this._tokenSecret = tokenSecret;
        this._tokenIssuer = new TokenIssuer(this._tokenSecret);
    }

    this.get = function(resource) {
        return this._send('get', resource);
    }

    this.post = function(resource, payload) {
        return this._send('post', resource, payload);
    }

    this.patch = function(resource, payload) {
        return this._send('patch', resource, payload);
    }

    this.delete = function(resource, payload) {
        return this._send('delete', resource, payload);
    }

    this._send = function(method, resource, payload) {
        let options = {};
        if (this._tokenSecret) {
            options = this._tokenIssuer.getRequestHeader();
        }

        options.url = (this._hostName || '') + resource;
        if (payload) {
            options.body = payload;
        }

        return new Promise((resolve, reject) => {
            request[method](options, (err, response) => {
                if (err || !response.statusCode.toString().startsWith('2')) {
                    return reject(err || response.body)
                }
                resolve(response.body);
            })
        });
    }
}

module.exports = Request;