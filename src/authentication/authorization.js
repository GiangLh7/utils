import { authorizationMethod, accessRoles } from './constanst';
import TokenIssuer from './tokenissuer';

class Authorization {
    _unauthorizedError = { code: 401, message: 'Unauthorized access to the resource!' };

    constructor(tokenSecret) {
        this._tokenSecret = tokenSecret;
        this._tokenIssuer = new TokenIssuer(tokenSecret);
        this.authStrategy = {
            key: this._tokenSecret,
            verifyOptions: { algorithms: ['HS256'] },
            validateFunc: this.validateToken
        }
    }

    validateToken(request, decodedToken, callback) {
        if (this._isSuperUserCredential(decodedToken)) {
            return callback(null, true, decodedToken);
        }
        const allowRoles = request.route.settings.plugins.authorization.role || [];
        if (!allowRoles.includes(decodedToken.role)) {
            callback(null, false, decodedToken);
        }
    }

    superUserAuthorization(payload, credentials, params) {
        const token = payload && payload.token ? payload.token : params.token;
        try {
            const decodedToken = this._tokenIssuer.decodeToken(token);
            if (this._isSuperUserCredential(decodedToken)) {
                return Promise.resolve();
            }
            return Promise.reject();
        }
        catch (err) {
            return Promise.reject();
        }
    }

    requestValidation(request, reply) {
        const credentials = request.auth.credentials;
        if (this._isSuperUserCredential(credentials)) {
            return reply.continue();
        }
        const routeAuthorizationSetting = request.route.settings.plugins.authorization;
        const validationFunc = this._getRouteValidationFunc(routeAuthorizationSetting, authorizationMethod.request);
        if (!validationFunc) {
            return reply.continue();
        }
        validationFunc(request.payload, credentials, request.params).then(() => {
            reply.continue();
        }, () => {
            reply.message(this._unauthorizedError).code(this._unauthorizedError.code);
        })
    }

    responeValidation(request, reply) {
        const credentials = request.auth.credentials;
        if (this._isSuperUserCredential(credentials)) {
            return reply.continue();
        }
        const response = request.response;
        const routeAuthorizationSetting = request.route.settings.plugins.authorization;
        const validationFunc = this._getRouteValidationFunc(routeAuthorizationSetting, authorizationMethod.response);
        if (!validationFunc || response.statusCode !== 200) {
            return reply.continue();
        }
        validationFunc(response.body, credentials, request.params).then(() => {
            reply.continue();
        }, () => {
            reply.message(this._unauthorizedError).code(this._unauthorizedError.code);
        });
    }

    _isSuperUserCredential(credentials) {
        return credentials && credentials.role === accessRoles.superUser && credentials.userId === accessRoles.superUser;
    }

    _getRouteValidationFunc(routeAuthorizationSetting, validationMethod) {
        if (!routeAuthorizationSetting) {
            return null;
        }
        if (!routeAuthorizationSetting.validationMethod && validationMethod == authorizationMethod.request) {
            return routeAuthorizationSetting.validate;
        }

        if (routeAuthorizationSetting.validationMethod == validationMethod) {
            return routeAuthorizationSetting.validate;
        }

        return null;
    }
}

export default Authorization;