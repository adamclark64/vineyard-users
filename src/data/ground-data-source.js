"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class GroundDataSource {
    constructor(settings) {
        if (!settings)
            throw new Error("Missing settings argument.");
        this.userModel = settings.user_model || settings.model.User;
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
    }
    getUserModel() {
        return this.userModel;
    }
    usesRoles() {
        return this.userModel.trellis.properties.roles;
    }
    createUser(newUser) {
        return this.userModel.create(newUser);
    }
    getUser(id) {
        return this.userModel.get(id).exec();
    }
    getUserByFilter(filter) {
        return this.userModel.first(filter).exec();
    }
    getSessionCollection() {
        return this.sessionCollection;
    }
    getTempPasswordCollection() {
        return this.tempPasswordCollection;
    }
    getOneTimeCodeCollection() {
        return this.oneTimeCodeCollection;
    }
    getTempPassword(user) {
        return this.tempPasswordCollection.first({ user: user }).exec();
    }
    removeTempPassword(tempPassword) {
        return this.tempPasswordCollection.remove(tempPassword)
            .then(() => {
        });
    }
    createTempPassword(newTempPassword) {
        return this.tempPasswordCollection.create(newTempPassword);
    }
    createEmailCode(newEmailCode) {
        return this.emailVerificationCollection.create(newEmailCode);
    }
    getEmailCode(user) {
        return this.emailVerificationCollection.first({ user: user }).exec();
    }
    getOneTimeCode(user) {
        return null;
    }
    updateOneTimeCode(oneTimeCode, fields) {
        return null;
    }
}
exports.GroundDataSource = GroundDataSource;
//# sourceMappingURL=ground-data-source.js.map