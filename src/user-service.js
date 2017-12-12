"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const session = require('express-session');
const vineyard_lawn_1 = require("vineyard-lawn");
const lawn = require("vineyard-lawn");
const two_factor = require("./two-factor");
const session_store_1 = require("./session-store");
const bcrypt = require('bcrypt');
function sanitize(user) {
    const result = Object.assign({}, user);
    delete result.password;
    delete result.twoFactorSecret;
    return result;
}
function createDefaultSessionStore(userManager, expiration, secure) {
    return new session_store_1.SequelizeStore(userManager.getSessionCollection().getTableClient().getSequelizeModel(), {
        expiration: expiration,
        updateFrequency: 5 * 60 * 1000,
        secure: secure,
    });
}
exports.createDefaultSessionStore = createDefaultSessionStore;
// For backwards compatibility
function getTwoFactorEnabled(user) {
    if (typeof user.twoFactorEnabled == 'boolean')
        return user.twoFactorEnabled;
    return !!user.two_factor_enabled;
}
function getTwoFactorSecret(user) {
    if (typeof user.twoFactorSecret == 'string')
        return user.twoFactorSecret;
    return user.two_factor_secret || '';
}
class UserService {
    constructor(app, userManager, cookie, sessionStore = createDefaultSessionStore(userManager, cookie.maxAge, cookie.secure)) {
        this.userManager = this.user_manager = userManager;
        if (!cookie.secret)
            throw new Error("UserService settings.secret cannot be empty.");
        app.use(session({
            secret: cookie.secret,
            store: sessionStore,
            cookie: cookie,
            resave: false,
            saveUninitialized: true
        }));
        // Backwards compatibility
        const self = this;
        self.login = () => {
            return (request) => this.loginWithUsername(request);
        };
        self.create_login_handler = () => {
            return (request) => this.loginWithUsername(request);
        };
        self.create_login_2fa_handler = () => {
            return (request) => this.checkUsernameOrEmailLogin(request)
                .then(user => {
                this.checkTwoFactor(user, request);
                return this.finishLogin(request, user);
            });
        };
        self.createLogin2faHandlerWithBackup = () => {
            return (request) => this.login2faWithBackup(request);
        };
        self.createLogoutHandler = () => {
            return (request) => this.logout(request);
        };
        self.create_logout_handler = () => {
            return self.createLogoutHandler();
        };
    }
    _checkLogin(filter, password) {
        return this.userManager.getUserByFilter(filter)
            .then(user => {
            if (!user)
                throw new vineyard_lawn_1.Bad_Request('Invalid credentials.', { key: 'invalid-credentials' });
            return bcrypt.compare(password, user.password)
                .then((success) => success
                ? user
                : this.checkTempPassword(user, password));
        });
    }
    checkTempPassword(user, password) {
        return this.userManager.matchTempPassword(user, password)
            .then(success => {
            if (!success)
                throw new vineyard_lawn_1.Bad_Request('Invalid credentials.', { key: 'invalid-credentials' });
            return user;
        });
    }
    /**
     * Compares a plain text password with a salted password.
     *
     * @param password  Plain text password
     *
     * @param hash  Salted password
     *
     */
    checkPassword(password, hash) {
        return bcrypt.compare(password, hash);
    }
    /**
     * Checks login credentials using a password and a username or email
     *
     * @param request  Vineyard Lawn request
     *
     */
    checkUsernameOrEmailLogin(request) {
        const data = request.data;
        const filter = data.username
            ? { username: data.username }
            : { email: data.email };
        return this._checkLogin(filter, data.password);
    }
    checkEmailLogin(request) {
        const data = request.data;
        return this._checkLogin({ email: data.email }, data.password);
    }
    finishLogin(request, user) {
        request.session.user = user.id;
        return sanitize(user);
    }
    loginWithUsername(request) {
        return this.checkUsernameOrEmailLogin(request)
            .then(user => this.finishLogin(request, user));
    }
    checkTwoFactor(user, request) {
        if (getTwoFactorEnabled(user) && !two_factor.verifyTwoFactorToken(getTwoFactorSecret(user), request.data.twoFactor))
            throw new vineyard_lawn_1.Bad_Request('Invalid Two Factor Authentication code.', { key: "invalid-2fa" });
    }
    login2faWithBackup(request) {
        return this.checkUsernameOrEmailLogin(request)
            .then(user => {
            const currentUser = user;
            if (getTwoFactorEnabled(user) && !two_factor.verifyTwoFactorToken(getTwoFactorSecret(user), request.data.twoFactor))
                return this.verify2faOneTimeCode(request, currentUser).then(backupCodeCheck => {
                    if (!backupCodeCheck)
                        throw new vineyard_lawn_1.Bad_Request('Invalid Two Factor Authentication code.', { key: "invalid-2fa" });
                    return this.finishLogin(request, currentUser);
                });
            return this.finishLogin(request, currentUser);
        });
    }
    verify2faOneTimeCode(request, user) {
        return this.userManager.getUserOneTimeCode(user).then((code) => {
            if (!code) {
                return false;
            }
            return this.userManager.compareOneTimeCode(request.data.twoFactor, code).then(pass => {
                if (!pass) {
                    return false;
                }
                return this.userManager.setOneTimeCodeToUnavailable(code)
                    .then(() => {
                    request.session.oneTimeCodeUsed = true;
                    return true;
                });
            });
        });
    }
    logout(request) {
        if (!request.session.user)
            throw new vineyard_lawn_1.BadRequest('Already logged out.', { key: 'already-logged-out' });
        request.session.user = null;
        return Promise.resolve({});
    }
    getUser(usernameOrUser) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof usernameOrUser === 'string')
                return this.userManager.getUserByFilter({ username: usernameOrUser });
            else if (typeof usernameOrUser === 'object')
                return Promise.resolve(usernameOrUser);
            else
                throw new Error("Invalid username or user.");
        });
    }
    createTempPassword(usernameOrUser) {
        return __awaiter(this, void 0, void 0, function* () {
            const userOrUndefined = yield this.getUser(usernameOrUser);
            if (!userOrUndefined)
                return Promise.resolve(new vineyard_lawn_1.BadRequest("Invalid user"));
            const user = userOrUndefined;
            return this.userManager.getTempPassword(user)
                .then(tempPassword => {
                if (!tempPassword) {
                    const passwordString = Math.random().toString(36).slice(2);
                    return this.userManager.hashPassword(passwordString)
                        .then(hashedPassword => this.userManager.getTempPasswordCollection().create({
                        user: user,
                        password: hashedPassword
                    }))
                        .then(() => {
                        return {
                            tempPassword: passwordString,
                            user: user
                        };
                    });
                }
                else {
                    throw new vineyard_lawn_1.BadRequest("A temporary password has already been created. Please try again at a later time.", {
                        key: 'existing-temp-pass'
                    });
                }
            });
        });
    }
    require_logged_in(request) {
        if (!request.session.user)
            throw new lawn.Needs_Login();
    }
    getSanitizedUser(id) {
        return this.userManager.getUser(id)
            .then(sanitize);
    }
    addUserToRequest(request) {
        if (request.user)
            return Promise.resolve(request.user);
        return this.userManager.getUser(request.session.user)
            .then(user => {
            if (user)
                return request.user = sanitize(user);
            else
                return undefined;
        });
    }
    loadValidationHelpers(ajv) {
        ajv.addSchema(require('./validation/helpers.json'));
    }
    fieldExists(request, fieldOptions) {
        const keyName = request.data.key;
        const value = request.data.value;
        if (fieldOptions.indexOf(keyName) == -1)
            throw new vineyard_lawn_1.Bad_Request('Invalid user field', {
                key: 'invalid-user-field',
                data: { field: keyName }
            });
        return this.userManager.fieldExists(keyName, value)
            .then(result => ({
            exists: result
        }));
    }
    getModel() {
        return this.userManager;
    }
}
exports.UserService = UserService;
class User_Service extends UserService {
    constructor(app, UserManager, settings) {
        super(app, UserManager, settings);
    }
}
exports.User_Service = User_Service;
//# sourceMappingURL=user-service.js.map