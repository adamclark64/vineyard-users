"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const utility_1 = require("./utility");
const errors_1 = require("vineyard-lawn/source/errors");
const bcrypt = require('bcrypt');
class UserManager {
    constructor(db, settings) {
        this.db = db;
        if (!settings)
            throw new Error("Missing settings argument.");
        const self = this;
        this.userModel = self.UserModel = self.User_Model = self.user_model =
            settings.user_model || settings.model.User;
        if (settings.model) {
            settings.model.ground.addDefinitions({
                "Session": {
                    "primaryKeys": ["sid"],
                    "properties": {
                        "sid": {
                            "type": "string"
                        },
                        "user": {
                            "type": "uuid",
                            "nullable": true
                        },
                        "expires": {
                            "type": "datetime"
                        },
                        "data": {
                            "type": "string"
                        }
                    }
                },
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
                },
                "Onetimecode": {
                    "properties": {
                        "user": {
                            "type": "User"
                        },
                        "code": {
                            "type": "string"
                        },
                        "available": {
                            "type": "bool"
                        }
                    }
                },
            });
            const collections = settings.model.ground.collections;
            this.sessionCollection = collections.Session;
            this.tempPasswordCollection = collections.Session;
            this.emailVerificationCollection = collections.EmailVerification;
            this.oneTimeCodeCollection = collections.Onetimecode;
        }
        // Backwards compatibility
        self.create_user = this.createUser;
    }
    getUserModel() {
        return this.userModel;
    }
    hashPassword(password) {
        return bcrypt.hash(password, 10);
    }
    prepareNewUser(fields) {
        if (!fields.roles && this.userModel.trellis.properties.roles)
            fields.roles = [];
        if (typeof fields.email === 'string')
            fields.email = fields.email.toLowerCase();
        return this.hashPassword(fields.password)
            .then(salt_and_hash => {
            fields.password = salt_and_hash;
            return fields;
        });
    }
    prepare_new_user(fields) {
        return this.prepareNewUser(fields);
    }
    createUser(fields, uniqueField = 'username') {
        // this.sanitizeRequest(fields)
        const uniqueFields = Array.isArray(uniqueField) ? uniqueField : [uniqueField];
        return utility_1.promiseEach(uniqueFields, (field) => this.checkUniqueness(fields, field))
            .then(() => {
            return this.prepare_new_user(fields)
                .then(user => this.userModel.create(fields));
        });
    }
    getUser(id) {
        return this.userModel.get(id).exec();
    }
    getSessionCollection() {
        return this.sessionCollection;
    }
    getUserCollection() {
        return this.userModel;
    }
    getOneTimeCodeCollection() {
        return this.oneTimeCodeCollection;
    }
    tempPasswordHasExpired(tempPassword) {
        const expirationDate = new Date(tempPassword.created.getTime() + (6 * 60 * 60 * 1000));
        return new Date() > expirationDate;
    }
    emailCodeHasExpired(emailCode) {
        const expirationDate = new Date(emailCode.created.getTime() + (6 * 60 * 60 * 1000));
        return new Date() > expirationDate;
    }
    matchTempPassword(user, password) {
        if (!this.tempPasswordCollection)
            return Promise.resolve(false);
        return this.tempPasswordCollection.first({ user: user.id })
            .then((storedTempPass) => {
            if (!storedTempPass)
                return false;
            if (this.tempPasswordHasExpired(storedTempPass))
                return this.tempPasswordCollection.remove(storedTempPass)
                    .then(() => false);
            return bcrypt.compare(password, storedTempPass.password)
                .then((success) => {
                if (!success)
                    return false;
                return this.getUserCollection().update(user, {
                    password: storedTempPass.password
                })
                    .then(() => this.tempPasswordCollection.remove(storedTempPass))
                    .then(() => true);
            });
        });
    }
    getUserFromUsername(username) {
        return this.userModel.first({ username: username })
            .then(user => {
            if (!user)
                throw new errors_1.BadRequest("Invalid username: " + username);
            return user;
        });
    }
    getUserFromEmail(email) {
        return this.userModel.first({ email: email })
            .then(user => {
            if (!user)
                throw new errors_1.BadRequest("Invalid email: " + email);
            return user;
        });
    }
    _createTempPassword(user) {
        return this.getTempPassword(user)
            .then(tempPassword => {
            if (!tempPassword) {
                const passwordString = Math.random().toString(36).slice(2);
                return this.hashPassword(passwordString)
                    .then(hashedPassword => this.tempPasswordCollection.create({
                    user: user,
                    password: hashedPassword
                }))
                    .then(() => {
                    return {
                        password: passwordString,
                        username: user.username
                    };
                });
            }
            else {
                return Promise.resolve(undefined);
            }
        });
    }
    createTempPassword(username) {
        if (typeof username == 'string') {
            return this.getUserFromUsername(username)
                .then(user => this._createTempPassword(user));
        }
        else {
            return this._createTempPassword(username);
        }
    }
    createEmailCode(user) {
        return this.getEmailCode(user)
            .then(emailCode => {
            if (!emailCode) {
                const newEmlCode = Math.random().toString(36).slice(2);
                return this.emailVerificationCollection.create({
                    user: user,
                    code: newEmlCode
                })
                    .then(() => newEmlCode);
            }
            else {
                return Promise.resolve(emailCode.code);
            }
        });
    }
    verifyEmailCode(userId, submittedCode) {
        return this.userModel.first({ id: userId }).exec()
            .then(user => {
            if (!user)
                return false;
            return this.emailVerificationCollection.first({
                user: userId
            })
                .then(emailCode => {
                if (!emailCode || emailCode.code != submittedCode)
                    return Promise.resolve(false);
                return this.userModel.update(user, {
                    emailVerified: true
                })
                    .then(() => true);
            });
        });
    }
    getEmailCode(user) {
        return this.emailVerificationCollection.first({ user: user.id }).exec();
    }
    getTempPassword(user) {
        return this.tempPasswordCollection.first({ user: user.id }).exec();
    }
    getUserOneTimeCode(user) {
        return this.oneTimeCodeCollection.first({ user: user.id, available: true }).exec();
    }
    fieldExists(key, value) {
        const filter = {};
        filter[key] = value;
        return this.userModel.first(filter).exec()
            .then((user) => !!user);
    }
    compareOneTimeCode(oneTimeCode, codeRecord) {
        return Promise.resolve(oneTimeCode === codeRecord.code);
    }
    setOneTimeCodeToUnavailable(oneTimeCode) {
        return this.oneTimeCodeCollection.update(oneTimeCode, { available: false });
    }
    checkUniqueness(user, field = 'username') {
        return this.fieldExists(field, user[field])
            .then(result => {
            if (result) {
                throw new Error(`User validation error: ${field} must be unique`);
            }
        });
    }
    getTempPasswordCollection() {
        return this.tempPasswordCollection;
    }
}
exports.UserManager = UserManager;
class User_Manager extends UserManager {
    constructor(db, settings) {
        super(db, settings);
    }
}
exports.User_Manager = User_Manager;
//# sourceMappingURL=user-manager.js.map