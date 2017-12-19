"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const utility_1 = require("./utility");
const errors_1 = require("vineyard-lawn/source/errors");
const ground_data_source_1 = require("./data/ground-data-source");
const bcrypt = require('bcrypt');
class UserManager {
    constructor(dataSource, settings) {
        this.dataSource = this.dataSource || new ground_data_source_1.GroundDataSource(settings);
        const self = this;
        // Backwards compatibility
        self.create_user = this.createUser;
        self.prepare_new_user = this.prepareNewUser;
    }
    getUserModel() {
        return this.dataSource.getUserModel();
    }
    /**
     * Hashes a password using bcrypt.
     *
     * @param password  Plain text password
     *
     */
    hashPassword(password) {
        return bcrypt.hash(password, 10);
    }
    /**
     * Prepares a new user structure before being saved to the database.
     * Hashes the password, ensures the email is lowercase, and ensures the user.roles is at least an empty array.
     * This function is called by UserManager.createUser and rarely needs to be called directly.
     *
     * @param userFields  Initial user object
     *
     */
    prepareNewUser(userFields) {
        if (!userFields.roles && this.userModel.trellis.properties.roles)
            userFields.roles = [];
        if (typeof userFields.email === 'string')
            userFields.email = userFields.email.toLowerCase();
        return this.hashPassword(userFields.password)
            .then(salt_and_hash => {
            userFields.password = salt_and_hash;
            return userFields;
        });
    }
    /**
     * Saves a new user record to the database.
     * Hashes the password, ensures the email is lowercase, and ensures the user.roles is at least an empty array.
     *
     * @param userFields  Initial user object
     *
     * @param uniqueFields  An array of user field names that must be unique.
     *
     */
    createUser(userFields, uniqueFields = 'username') {
        const _uniqueFields = Array.isArray(uniqueFields) ? uniqueFields : [uniqueFields];
        return utility_1.promiseEach(_uniqueFields, (field) => this.checkUniqueness(userFields, field))
            .then(() => {
            return this.prepareNewUser(userFields)
                .then(user => this.dataSource.createUser(userFields));
        });
    }
    /**
     * Fetches a user from the database.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param id  User identity string or object
     *
     */
    getUser(id) {
        return this.dataSource.getUser(typeof id === 'string' ? id : id.id);
    }
    getUserByFilter(filter) {
        return this.dataSource.getUserByFilter(filter);
    }
    getSessionCollection() {
        return this.dataSource.getSessionCollection();
    }
    getUserCollection() {
        return this.dataSource.getUserCollection();
    }
    getOneTimeCodeCollection() {
        return this.dataSource.getOneTimeCodeCollection();
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
    /**
     * Finds a user that has a particular username.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param username  The value to search for
     *
     */
    getUserFromUsername(username) {
        return this.dataSource.getUserByFilter({ username: username })
            .then(user => {
            if (!user)
                throw new errors_1.BadRequest("Invalid username: " + username);
            return user;
        });
    }
    /**
     * Finds a user that has a particular email address.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param email  The value to search for
     *
     */
    getUserFromEmail(email) {
        return this.dataSource.getUserByFilter({ email: email })
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
                    .then(hashedPassword => this.dataSource.createTempPassword({
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
                return this.dataSource.createEmailCode({
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
        return this.getUser(userId)
            .then(user => {
            if (!user)
                return false;
            return this.dataSource.getEmailCode(user)
                .then(emailCode => {
                if (!emailCode || emailCode.code != submittedCode)
                    return Promise.resolve(false);
                return this.dataSource.updateEmailCode(user)
                    .then(() => true);
            });
        });
    }
    getEmailCode(user) {
        return this.dataSource.getEmailCode(user);
    }
    getTempPassword(user) {
        return this.dataSource.getTempPassword(user);
    }
    getUserOneTimeCode(user) {
        return this.dataSource.getOneTimeCode(user);
    }
    fieldExists(key, value) {
        const filter = {};
        filter[key] = value;
        return this.getUserByFilter(filter)
            .then((user) => !!user);
    }
    compareOneTimeCode(oneTimeCode, codeRecord) {
        return Promise.resolve(oneTimeCode === codeRecord.code);
    }
    setOneTimeCodeToUnavailable(oneTimeCode) {
        return this.dataSource.updateOneTimeCode(oneTimeCode, { available: false });
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
        return this.dataSource.getTempPasswordCollection();
    }
}
exports.UserManager = UserManager;
module.exports.User_Manager = UserManager;
//# sourceMappingURL=user-manager.js.map