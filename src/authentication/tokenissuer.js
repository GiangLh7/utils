const jsonWebToken = require('jsonwebtoken');
const accessRoles = require('./constanst').accessRoles;

function TokenIssuer(tokenSecret) {
    this._cachedTokens = {};
    this._tokenSecret = tokenSecret;

    this.issueToken = (userId, role) => {
        userId = userId || accessRoles.superUser;
        role = role || accessRoles.superUser;
        let cachedToken = this._cachedTokens[userId];
        if (cachedToken || jsonWebToken.verify(cachedToken, this._tokenSecret)) {
            return cachedToken;
        }
        const userObj = {
            userId,
            role
        };
        cachedToken = jsonWebToken.sign(userObj, this._tokenSecret, { noTimestamp: true });
        return cachedToken;
    }

    this.decodeToken = (token) => {
        return jsonWebToken.verify(token, this._tokenSecret);
    }

    this.generateToken = (encodingData, encodingSecret, expirationTime) => {
        return (expirationTime)? jsonWebToken.sign(encodingData, encodingSecret, {expiresIn: expirationTime}) :
            jsonWebToken.sign(encodingData, encodingSecret);
    }

    this.verifyIdToken = (token, encodingSecret, ignoreExpiration) => {
        let decoded = '';
        try {
            decoded = ignoreExpiration ?
                jsonWebToken.verify(token, encodingSecret, { ignoreExpiration: true }) :
                jsonWebToken.verify(token, encodingSecret);
        } catch (err) {
            decoded = '';
        }
        return decoded;
    }

    this.getRequestHeader = (userId) => {
        const token = this.issueToken(userId);
        const headerOption = {
            json: true,
            headers: {
                Authorization: `Bearer ${token}`
            }
        }

        return headerOption;
    }
}

module.exports = TokenIssuer;