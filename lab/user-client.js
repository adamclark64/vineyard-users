"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var src_1 = require("../src");
var UserClient = /** @class */ (function () {
    function UserClient(webClient) {
        this.webClient = webClient;
    }
    UserClient.prototype.prepareTwoFactor = function () {
        var _this = this;
        return this.webClient.get('user/2fa')
            .then(function (data) { return _this.webClient.post('user/2fa', {
            twoFactor: src_1.getTwoFactorToken(data.secret)
        })
            .then(function () { return _this.twoFactorSecret = data.secret; }); });
    };
    UserClient.prototype.register = function (createUser) {
        var _this = this;
        this.userIdentifier = createUser;
        this.password = createUser.password;
        createUser.twoFactorSecret = this.twoFactorSecret;
        return this.prepareTwoFactor()
            .then(function (twoFactorSecret) { return _this.webClient.post('user', createUser); })
            .then(function (user) {
            _this.createUserResponse = user;
            return _this.createUserResponse;
        });
    };
    UserClient.prototype.loginWithUsername = function () {
        var userIdentifier = this.userIdentifier;
        return this.webClient.post('user/login', {
            username: userIdentifier.username,
            password: this.password,
            twoFactor: src_1.getTwoFactorToken(this.twoFactorSecret)
        });
    };
    UserClient.prototype.loginWithEmail = function () {
        var userIdentifier = this.userIdentifier;
        return this.webClient.post('user/login', {
            email: userIdentifier.email,
            password: this.password,
            twoFactor: src_1.getTwoFactorToken(this.twoFactorSecret)
        });
    };
    UserClient.prototype.logout = function () {
        return this.webClient.post('user/logout');
    };
    UserClient.prototype.getWebClient = function () {
        return this.webClient;
    };
    UserClient.prototype.getUser = function () {
        return this.createUserResponse;
    };
    return UserClient;
}());
exports.UserClient = UserClient;
//# sourceMappingURL=user-client.js.map