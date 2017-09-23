import TokenIssuer from '../authentication/tokenissuer';
const request = require('request');

class Request {

    constructor(hostName, tokenSecret) {
        this._hostName = hostName;
        if(tokenSecret) {
            this._tokenSecret = tokenSecret;
            this._tokenIssuer = new TokenIssuer(this._tokenSecret);
        }
    }

    get(resource) {
        return this._send('get', resource);
    }

    post(resource, payload) {
        return this._send('post', resource, payload);
    }

    patch(resource, payload) {
        return this._send('patch', resource, payload);
    }

    delete(resource, payload) {
        return this._send('delete', resource, payload);
    }

    _send(method, resource, payload) {
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
        })
    }
}

export default Request;