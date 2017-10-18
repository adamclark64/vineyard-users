"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
var session = require('express-session');
var vineyard_lawn_1 = require("vineyard-lawn");
var lawn = require("vineyard-lawn");
var two_factor = require("./two-factor");
var bcrypt = require('bcrypt');
function sanitize(user) {
    var result = Object.assign({}, user);
    delete result.password;
    return result;
}
function createDefaultSessionStore(userManager) {
    var SequelizeStore = require('connect-session-sequelize')(session.Store);
    return new SequelizeStore({
        db: userManager.db,
        table: 'session',
        extendDefaultFields: function (defaults, session) {
            return {
                expires: defaults.expires,
                user: session.user
            };
        },
        checkExpirationInterval: 5 * 60 * 1000
    });
}
exports.createDefaultSessionStore = createDefaultSessionStore;
var UserService = (function () {
    function UserService(app, userManager, settings, sessionStore) {
        if (sessionStore === void 0) { sessionStore = createDefaultSessionStore(userManager); }
        this.userManager = this.user_manager = userManager;
        if (!settings.secret)
            throw new Error("UserService settings.secret cannot be empty.");
        app.use(session({
            secret: settings.secret,
            store: sessionStore,
            cookie: settings.cookie || {},
            resave: false,
            saveUninitialized: true
        }));
    }
    UserService.prototype.checkTempPassword = function (user, password) {
        return this.userManager.matchTempPassword(user, password)
            .then(function (success) {
            if (!success)
                throw new vineyard_lawn_1.Bad_Request('Incorrect username or password.', { key: 'invalid-credentials' });
            return user;
        });
    };
    UserService.prototype.checkPassword = function (password, hash) {
        return bcrypt.compare(password, hash);
    };
    UserService.prototype._checkLogin = function (filter, password) {
        var _this = this;
        return this.userManager.User_Model.first(filter)
            .then(function (user) {
            if (!user)
                throw new vineyard_lawn_1.Bad_Request('Incorrect username or password.', { key: 'invalid-credentials' });
            return bcrypt.compare(password, user.password)
                .then(function (success) { return success
                ? user
                : _this.checkTempPassword(user, password); });
        });
    };
    UserService.prototype.checkUsernameOrEmailLogin = function (request) {
        var data = request.data;
        var filter = data.username
            ? { username: data.username }
            : { email: data.email };
        return this._checkLogin(filter, data.password);
    };
    UserService.prototype.checkEmailLogin = function (request) {
        var data = request.data;
        return this._checkLogin({ email: data.email }, data.password);
    };
    UserService.prototype.finishLogin = function (request, user) {
        request.session.user = user.id;
        return sanitize(user);
    };
    UserService.prototype.login = function (request) {
        var _this = this;
        return this.checkUsernameOrEmailLogin(request)
            .then(function (user) { return _this.finishLogin(request, user); });
    };
    UserService.prototype.create_login_handler = function () {
        var _this = this;
        return function (request) { return _this.login(request); };
    };
    UserService.prototype.checkTwoFactor = function (user, request) {
        if (user.two_factor_enabled && !two_factor.verify_2fa_token(user.two_factor_secret, request.data.twoFactor))
            throw new vineyard_lawn_1.Bad_Request('Invalid Two Factor Authentication code.', { key: "invalid-2fa" });
    };
    UserService.prototype.create_login_2fa_handler = function () {
        var _this = this;
        return function (request) { return _this.checkUsernameOrEmailLogin(request)
            .then(function (user) {
            _this.checkTwoFactor(user, request);
            return _this.finishLogin(request, user);
        }); };
    };
    UserService.prototype.createLogin2faHandlerWithBackup = function () {
        var _this = this;
        var currentUser;
        return function (request) { return _this.checkUsernameOrEmailLogin(request)
            .then(function (user) {
            currentUser = user;
            if (user.two_factor_enabled && !two_factor.verify_2fa_token(user.two_factor_secret, request.data.twoFactor)) {
                return _this.verify2faOneTimeCode(request, currentUser).then(function (backupCodeCheck) {
                    if (!backupCodeCheck)
                        throw new vineyard_lawn_1.Bad_Request('Invalid Two Factor Authentication code.', { key: "invalid-2fa" });
                    return _this.finishLogin(request, currentUser);
                });
            }
            return _this.finishLogin(request, currentUser);
        }); };
    };
    UserService.prototype.verify2faOneTimeCode = function (request, user) {
        var _this = this;
        return this.userManager.getUserOneTimeCode(user).then(function (code) {
            if (!code)
                return false;
            return _this.userManager.compareOneTimeCode(request.data.twoFactor, code).then(function (pass) {
                if (!pass) {
                    return false;
                }
                return _this.userManager.setOneTimeCodeToUnavailable(code)
                    .then(function () {
                    request.session.oneTimeCodeUsed = true;
                    return true;
                });
            });
        });
    };
    UserService.prototype.logout = function (request) {
        if (!request.session.user)
            throw new vineyard_lawn_1.BadRequest('Already logged out.', { key: 'already-logged-out' });
        request.session.user = null;
        return Promise.resolve({});
    };
    UserService.prototype.createLogoutHandler = function () {
        var _this = this;
        return function (request) { return _this.logout(request); };
    };
    UserService.prototype.create_logout_handler = function () {
        return this.createLogoutHandler();
    };
    UserService.prototype.create_get_user_endpoint = function (app, overrides) {
        var _this = this;
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.get,
            path: "user",
            action: function (request) {
                return _this.userManager.getUser(request.session.user)
                    .then(function (user) {
                    if (!user)
                        throw new vineyard_lawn_1.BadRequest("Invalid user ID", { key: 'invalid-user-id' });
                    return sanitize(user);
                });
            }
        }, overrides);
    };
    UserService.prototype.createTempPassword = function (username) {
        var _this = this;
        return this.userManager.user_model.first({ username: username })
            .then(function (user) {
            if (!user)
                throw new vineyard_lawn_1.BadRequest("Invalid username", {
                    key: "invalid-username",
                    data: { username: username }
                });
            return _this.userManager.getTempPassword(user)
                .then(function (tempPassword) {
                if (!tempPassword) {
                    var passwordString_1 = Math.random().toString(36).slice(2);
                    return _this.userManager.hashPassword(passwordString_1)
                        .then(function (hashedPassword) { return _this.userManager.tempPasswordCollection.create({
                        user: user,
                        password: hashedPassword
                    }); })
                        .then(function () {
                        return {
                            tempPassword: passwordString_1,
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
    };
    UserService.prototype.create_login_endpoint = function (app, overrides) {
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.post,
            path: "user/login",
            action: this.create_login_handler()
        }, overrides);
    };
    UserService.prototype.create_logout_endpoint = function (app, overrides) {
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.post,
            path: "user/logout",
            action: this.create_logout_handler()
        }, overrides);
    };
    UserService.prototype.create_all_endpoints = function (app) {
        this.create_get_user_endpoint(app);
        this.create_login_endpoint(app);
        this.create_logout_endpoint(app);
    };
    UserService.prototype.require_logged_in = function (request) {
        if (!request.session.user)
            throw new lawn.Needs_Login();
    };
    UserService.prototype.addUserToRequest = function (request) {
        if (request.user)
            return Promise.resolve(request.user);
        return this.userManager.getUser(request.session.user)
            .then(function (user) {
            if (user)
                return request.user = sanitize(user);
            else
                return undefined;
        });
    };
    UserService.prototype.loadValidationHelpers = function (ajv) {
        ajv.addSchema(require('./validation/helpers.json'));
    };
    UserService.prototype.fieldExists = function (request, fieldOptions) {
        var keyName = request.data.key;
        var value = request.data.value;
        if (fieldOptions.indexOf(keyName) == -1)
            throw new vineyard_lawn_1.Bad_Request('Invalid user field', {
                key: 'invalid-user-field',
                data: { field: keyName }
            });
        return this.userManager.fieldExists(keyName, value)
            .then(function (result) { return ({
            exists: result
        }); });
    };
    return UserService;
}());
exports.UserService = UserService;
var User_Service = (function (_super) {
    __extends(User_Service, _super);
    function User_Service(app, UserManager, settings) {
        return _super.call(this, app, UserManager, settings) || this;
    }
    return User_Service;
}(UserService));
exports.User_Service = User_Service;
//# sourceMappingURL=user-service.js.map