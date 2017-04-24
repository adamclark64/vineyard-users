"use strict";
var session = require('express-session');
var vineyard_lawn_1 = require('vineyard-lawn');
var lawn = require('vineyard-lawn');
var Sequelize = require('sequelize');
var bcrypt = require('bcrypt');
var User_Manager = (function () {
    function User_Manager(app, db, settings) {
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
        var SequelizeStore = require('connect-session-sequelize')(session.Store);
        this.User_Model = settings.user_model;
        this.Session_Model = db.define('session', {
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
        app.use(session({
            secret: settings.secret,
            store: new SequelizeStore({
                db: db,
                table: 'session',
                extendDefaultFields: function (defaults, session) {
                    return {
                        expires: defaults.expires,
                        user: session.user
                    };
                }
            }),
            cookie: settings.cookie || {},
            resave: false,
            saveUninitialized: true
        }));
    }
    // get_user(username): Promise<User> {
    //   return this.User_Model.findOne({username: username})
    //     .then((user: User_With_Password) => {
    //       if (!)
    //       if (user) {
    //         delete user.password
    //       }
    //       return user
    //     })
    // }
    User_Manager.prototype.create_user = function (fields) {
        var _this = this;
        if (!fields.username)
            throw new lawn.Bad_Request("Missing username field");
        if (!fields.password)
            throw new lawn.Bad_Request("Missing password field");
        return bcrypt.hash(fields.password, 10)
            .then(function (salt_and_hash) {
            fields.password = salt_and_hash;
            return _this.User_Model.create(fields);
        });
    };
    User_Manager.prototype.sanitize = function (user) {
        var result = Object.assign({}, user);
        delete result.password;
        delete result.salt;
        return result;
    };
    User_Manager.prototype.create_login_handler = function () {
        var _this = this;
        return function (request) {
            return _this.User_Model.first({ username: request.data.username })
                .then(function (response) {
                if (!response)
                    throw new vineyard_lawn_1.Bad_Request('Incorrect username or password.');
                return bcrypt.compare(request.data.password, response.password)
                    .then(function (success) {
                    if (!success)
                        throw new vineyard_lawn_1.Bad_Request('Incorrect username or password.');
                    var user = response;
                    request.session.user = user.id;
                    return _this.sanitize(user);
                });
            });
        };
    };
    User_Manager.prototype.create_logout_handler = function () {
        return function (request) {
            if (!request.session.user)
                throw new vineyard_lawn_1.Bad_Request('Already logged out.');
            request.session.user = null;
            return Promise.resolve({});
        };
    };
    User_Manager.prototype.create_user_endpoint = function (app, overrides) {
        var _this = this;
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.get,
            path: "user",
            action: function (request) {
                return _this.User_Model.get(request.session.user)
                    .then(function (response) {
                    if (!response)
                        throw new vineyard_lawn_1.Bad_Request('Invalid user id.');
                    var user = response.dataValues;
                    return _this.sanitize(user);
                });
            }
        }, overrides);
    };
    User_Manager.prototype.create_login_endpoint = function (app, overrides) {
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.post,
            path: "user/login",
            action: this.create_login_handler()
        }, overrides);
    };
    User_Manager.prototype.create_logout_endpoint = function (app, overrides) {
        if (overrides === void 0) { overrides = {}; }
        lawn.create_endpoint_with_defaults(app, {
            method: vineyard_lawn_1.Method.post,
            path: "user/logout",
            action: this.create_logout_handler()
        }, overrides);
    };
    User_Manager.prototype.create_all_endpoints = function (app) {
        this.create_user_endpoint(app);
        this.create_login_endpoint(app);
        this.create_logout_endpoint(app);
    };
    User_Manager.prototype.require_logged_in = function (request) {
        if (!request.session.user)
            throw new lawn.Needs_Login();
    };
    return User_Manager;
}());
exports.User_Manager = User_Manager;
//# sourceMappingURL=User_Manager.js.map