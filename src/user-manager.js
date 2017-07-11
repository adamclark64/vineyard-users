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
var Sequelize = require("sequelize");
var utility_1 = require("./utility");
var bcrypt = require('bcrypt');
var UserManager = (function () {
    function UserManager(db, settings) {
        this.db = db;
        if (!settings)
            throw new Error("Missing settings argument.");
        if (!settings.user_model)
            throw new Error("Missing user_model settings argument.");
        this.table_keys = settings.table_keys || {
            id: "id",
            username: "username,",
            password: "password"
        };
        this.User_Model = this.user_model = settings.user_model;
        this.sessionCollection = db.define('session', {
            sid: {
                type: Sequelize.STRING,
                primaryKey: true
            },
            user: Sequelize.UUID,
            expires: Sequelize.DATE,
            data: Sequelize.TEXT
        }, {
            underscored: true,
            createdAt: 'created',
            updatedAt: 'modified',
        });
        if (settings.model) {
            settings.model.ground.addDefinitions({
                "TempPassword": {
                    "primary": "user",
                    "properties": {
                        "user": {
                            "type": "guid"
                        },
                        "password": {
                            "type": "string"
                        }
                    }
                },
                "EmailVerification": {
                    "primary": "user",
                    "properties": {
                        "user": {
                            "type": "User"
                        },
                        "code": {
                            "type": "string"
                        }
                    }
                }
            });
            this.tempPasswordCollection = settings.model.TempPassword;
            this.emailVerificationCollection = settings.model.ground.collections.EmailVerification;
        }
    }
    UserManager.prototype.hashPassword = function (password) {
        return bcrypt.hash(password, 10);
    };
    UserManager.prototype.prepareNewUser = function (fields) {
        if (!fields.roles && this.User_Model.trellis.properties.roles)
            fields.roles = [];
        if (typeof fields.email === 'string')
            fields.email = fields.email.toLowerCase();
        return this.hashPassword(fields.password)
            .then(function (salt_and_hash) {
            fields.password = salt_and_hash;
            return fields;
        });
    };
    UserManager.prototype.prepare_new_user = function (fields) {
        return this.prepareNewUser(fields);
    };
    UserManager.prototype.create_user = function (fields, uniqueField) {
        if (uniqueField === void 0) { uniqueField = 'username'; }
        return this.createUser(fields, uniqueField);
    };
    UserManager.prototype.createUser = function (fields, uniqueField) {
        var _this = this;
        if (uniqueField === void 0) { uniqueField = 'username'; }
        // this.sanitizeRequest(fields)
        var uniqueFields = Array.isArray(uniqueField) ? uniqueField : [uniqueField];
        return utility_1.promiseEach(uniqueFields, function (field) { return _this.checkUniqueness(fields, field); })
            .then(function () {
            return _this.prepare_new_user(fields)
                .then(function (user) { return _this.User_Model.create(fields); });
        });
    };
    UserManager.prototype.getUser = function (id) {
        return this.User_Model.get(id);
    };
    UserManager.prototype.getSessionCollection = function () {
        return this.sessionCollection;
    };
    UserManager.prototype.getUserCollection = function () {
        return this.user_model;
    };
    UserManager.prototype.validateParameters = function (request) {
        var invalidUserChars = request.username.match(/[^\w_]/g);
        var invalidPassChars = request.username.match(/[^\w_\-?!]/g);
        return {
            valid: (!invalidUserChars && !invalidPassChars),
            invalidChars: {
                username: invalidUserChars,
                password: invalidPassChars
            }
        };
    };
    UserManager.prototype.tempPasswordHasExpired = function (tempPassword) {
        var expirationDate = new Date(tempPassword.created.getTime() + (6 * 60 * 60 * 1000));
        return new Date() > expirationDate;
    };
    UserManager.prototype.emailCodeHasExpired = function (emailCode) {
        var expirationDate = new Date(emailCode.created.getTime() + (6 * 60 * 60 * 1000));
        return new Date() > expirationDate;
    };
    UserManager.prototype.matchTempPassword = function (user, password) {
        var _this = this;
        if (!this.tempPasswordCollection)
            return Promise.resolve(false);
        return this.tempPasswordCollection.firstOrNull({ user: user.id })
            .then(function (storedTempPass) {
            if (!storedTempPass)
                return false;
            if (_this.tempPasswordHasExpired(storedTempPass))
                return _this.tempPasswordCollection.remove(storedTempPass)
                    .then(function () { return false; });
            return bcrypt.compare(password, storedTempPass.password)
                .then(function (success) {
                if (!success)
                    return false;
                return _this.getUserCollection().update(user, {
                    password: storedTempPass.password
                })
                    .then(function () { return _this.tempPasswordCollection.remove(storedTempPass); })
                    .then(function () { return true; });
            });
        });
    };
    UserManager.prototype.createTempPassword = function (username) {
        var _this = this;
        return this.user_model.firstOrNull({ username: username })
            .then(function (user) {
            if (!user)
                throw new Error("Invalid username: " + username);
            return _this.getTempPassword(user)
                .then(function (tempPassword) {
                if (!tempPassword) {
                    var passwordString_1 = Math.random().toString(36).slice(2);
                    return _this.hashPassword(passwordString_1)
                        .then(function (hashedPassword) { return _this.tempPasswordCollection.create({
                        user: user,
                        password: hashedPassword
                    }); })
                        .then(function () {
                        return {
                            password: passwordString_1,
                            username: user.username
                        };
                    });
                }
                else {
                    return null;
                }
            });
        });
    };
    UserManager.prototype.createEmailCode = function (user) {
        var _this = this;
        return this.getEmailCode(user)
            .then(function (emailCode) {
            if (!emailCode) {
                var newEmlCode_1 = Math.random().toString(36).slice(2);
                return _this.emailVerificationCollection.create({
                    user: user,
                    code: newEmlCode_1
                })
                    .then(function () {
                    return newEmlCode_1;
                });
            }
            else {
                return emailCode;
            }
        });
    };
    UserManager.prototype.verifyEmailCode = function (userId, submittedCode) {
        var _this = this;
        return this.user_model.firstOrNull({ id: userId })
            .then(function (user) {
            if (!user)
                return false;
            return _this.emailVerificationCollection.firstOrNull({
                user: userId
            })
                .then(function (emailCode) {
                if (!emailCode || emailCode.code != submittedCode)
                    return false;
                return _this.user_model.update(user, {
                    emailVerified: true
                })
                    .then(function () { return _this.emailVerificationCollection.remove(emailCode); })
                    .then(function () { return true; });
            });
        });
    };
    UserManager.prototype.getEmailCode = function (user) {
        return this.emailVerificationCollection.firstOrNull({ user: user.id });
    };
    UserManager.prototype.getTempPassword = function (user) {
        return this.tempPasswordCollection.firstOrNull({ user: user.id });
    };
    UserManager.prototype.sanitizeRequest = function (request) {
        var check = this.validateParameters(request);
        if (check.valid !== true) {
            throw new Error("Parameters contain the following invalid characters " + check.invalidChars);
        }
    };
    UserManager.prototype.fieldExists = function (key, value) {
        var filter = {};
        filter[key] = value;
        return this.User_Model.first_or_null(filter)
            .then(function (user) { return !!user; });
    };
    UserManager.prototype.checkUniqueness = function (user, field) {
        if (field === void 0) { field = 'username'; }
        return this.fieldExists(field, user[field])
            .then(function (result) {
            if (result) {
                throw new Error("User validation error: " + field + " must be unique");
            }
        });
    };
    UserManager.prototype.getTempPasswordCollection = function () {
        return this.tempPasswordCollection;
    };
    return UserManager;
}());
exports.UserManager = UserManager;
var User_Manager = (function (_super) {
    __extends(User_Manager, _super);
    function User_Manager(db, settings) {
        return _super.call(this, db, settings) || this;
    }
    return User_Manager;
}(UserManager));
exports.User_Manager = User_Manager;
//# sourceMappingURL=user-manager.js.map