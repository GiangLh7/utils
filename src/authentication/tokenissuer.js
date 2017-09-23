const jsonWebToken = require('jsonwebtoken');
import { accessRoles } from  './constanst'

class TokenIssuer {
    constructor(tokenSecret) {
        this._cachedTokens = {};
        this._tokenSecret = tokenSecret;
    }

    issueToken(userId, role) {
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

    decodeToken(token) {
        return jsonWebToken.verify(token, this._tokenSecret);
    }

    getRequestHeader(userId) {
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

export default TokenIssuer;
