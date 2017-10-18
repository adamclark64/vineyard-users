import {UserManager} from "./user-manager";

const session = require('express-session');
import {Method, HTTP_Error, Bad_Request, Request, BadRequest} from 'vineyard-lawn'
import * as lawn from 'vineyard-lawn'
import * as express from 'express'
import * as two_factor from './two-factor'
import {User, UserWithPassword} from "./User";

const bcrypt = require('bcrypt')

export interface ServiceSettings {
  secret: string
  cookie?: any
}

export type Service_Settings = ServiceSettings

function sanitize(user: UserWithPassword): User {
  const result = Object.assign({}, user)
  delete result.password
  return result
}

export function createDefaultSessionStore(userManager: UserManager) {
  const SequelizeStore = require('connect-session-sequelize')(session.Store)
  return new SequelizeStore({
    db: userManager.db,
    table: 'session',
    extendDefaultFields: function (defaults: any, session: any) {
      return {
        expires: defaults.expires,
        user: session.user
      };
    },
    checkExpirationInterval: 5 * 60 * 1000
  })
}

export class UserService {
  private userManager: UserManager
  private user_manager: UserManager

  constructor(app: express.Application, userManager: UserManager, settings: ServiceSettings,
              sessionStore: any = createDefaultSessionStore(userManager)) {

    this.userManager = this.user_manager = userManager

    if (!settings.secret)
      throw new Error("UserService settings.secret cannot be empty.")

    app.use(session({
      secret: settings.secret,
      store: sessionStore,
      cookie: settings.cookie || {},
      resave: false,
      saveUninitialized: true
    }))
  }

  private checkTempPassword(user: User, password: string) {
    return this.userManager.matchTempPassword(user, password)
      .then(success => {
        if (!success)
          throw new Bad_Request('Incorrect username or password.', {key: 'invalid-credentials'})

        return user
      })
  }

  checkPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash)
  }

  private _checkLogin(filter: any, password: string) {
    return this.userManager.User_Model.first(filter)
      .then(user => {
        if (!user)
          throw new Bad_Request('Incorrect username or password.', {key: 'invalid-credentials'})

        return bcrypt.compare(password, user.password)
          .then((success: boolean) => success
            ? user
            : this.checkTempPassword(user, password)
          )
      })
  }

  private checkUsernameOrEmailLogin(request: Request): Promise<UserWithPassword> {
    const data = request.data

    const filter = data.username
      ? {username: data.username}
      : {email: data.email}

    return this._checkLogin(filter, data.password)
  }

  private checkEmailLogin(request: Request): Promise<UserWithPassword> {
    const data = request.data
    return this._checkLogin({email: data.email}, data.password)
  }

  private finishLogin(request: Request, user: UserWithPassword) {
    request.session.user = user.id
    return sanitize(user)
  }

  login(request: Request) {
    return this.checkUsernameOrEmailLogin(request)
      .then(user => this.finishLogin(request, user))
  }

  create_login_handler(): lawn.Response_Generator {
    return request => this.login(request)
  }


  checkTwoFactor(user: User, request: Request) {
    if (user.two_factor_enabled && !two_factor.verify_2fa_token(user.two_factor_secret, request.data.twoFactor))
      throw new Bad_Request('Invalid Two Factor Authentication code.', {key: "invalid-2fa"})
  }

  create_login_2fa_handler(): lawn.Response_Generator {
    return request => this.checkUsernameOrEmailLogin(request)
      .then(user => {
        this.checkTwoFactor(user, request)
        return this.finishLogin(request, user)
      })
  }

  createLogin2faHandlerWithBackup(): lawn.Response_Generator {
    let currentUser: UserWithPassword
    return request => this.checkUsernameOrEmailLogin(request)
      .then(user => {
        currentUser = user
        if (user.two_factor_enabled && !two_factor.verify_2fa_token(user.two_factor_secret, request.data.twoFactor)) {
          return this.verify2faOneTimeCode(request, currentUser).then(backupCodeCheck => {
            if (!backupCodeCheck)
              throw new Bad_Request('Invalid Two Factor Authentication code.', {key: "invalid-2fa"})
            return this.finishLogin(request, currentUser)
          })
        }
        return this.finishLogin(request, currentUser)
      })
  }

  private verify2faOneTimeCode(request: Request, user: User): Promise<boolean> {
    return this.userManager.getUserOneTimeCode(user).then(code => {
      if (!code)
        return false

      return this.userManager.compareOneTimeCode(request.data.twoFactor, code).then(pass => {
        if (!pass) {
          return false
        }
        return this.userManager.setOneTimeCodeToUnavailable(code)
          .then(() => {
            request.session.oneTimeCodeUsed = true
            return true
          })
      })
    })
  }

  logout(request: Request) {
    if (!request.session.user)
      throw new BadRequest('Already logged out.', {key: 'already-logged-out'})

    request.session.user = null
    return Promise.resolve({})
  }

  createLogoutHandler(): lawn.Response_Generator {
    return request => this.logout(request)
  }

  create_logout_handler(): lawn.Response_Generator {
    return this.createLogoutHandler()
  }

  create_get_user_endpoint(app: any, overrides: lawn.Optional_Endpoint_Info = {}) {
    lawn.create_endpoint_with_defaults(app, {
      method: Method.get,
      path: "user",
      action: request => {
        return this.userManager.getUser(request.session.user)
          .then(user => {
            if (!user)
              throw new BadRequest("Invalid user ID", {key: 'invalid-user-id'})

            return sanitize(user)
          })
      }
    }, overrides)
  }

  createTempPassword(username: string): Promise<any> {
    return this.userManager.user_model.first({username: username})
      .then(user => {
        if (!user)
          throw new BadRequest(
            "Invalid username",
            {
              key: "invalid-username",
              data: {username: username}
            }
          )

        return this.userManager.getTempPassword(user)
          .then(tempPassword => {
            if (!tempPassword) {
              const passwordString = Math.random().toString(36).slice(2)
              return this.userManager.hashPassword(passwordString)
                .then(hashedPassword => this.userManager.tempPasswordCollection.create({
                    user: user,
                    password: hashedPassword
                  })
                )
                .then(() => {
                  return {
                    tempPassword: passwordString,
                    user: user
                  }
                })
            } else {
              throw new BadRequest(
                "A temporary password has already been created. Please try again at a later time.",
                {
                  key: 'existing-temp-pass'
                }
              )
            }
          })
      })
  }

  create_login_endpoint(app: any, overrides: lawn.Optional_Endpoint_Info = {}) {
    lawn.create_endpoint_with_defaults(app, {
      method: Method.post,
      path: "user/login",
      action: this.create_login_handler()
    }, overrides)
  }

  create_logout_endpoint(app: any, overrides: lawn.Optional_Endpoint_Info = {}) {
    lawn.create_endpoint_with_defaults(app, {
      method: Method.post,
      path: "user/logout",
      action: this.create_logout_handler()
    }, overrides)
  }

  create_all_endpoints(app: any) {
    this.create_get_user_endpoint(app)
    this.create_login_endpoint(app)
    this.create_logout_endpoint(app)
  }

  require_logged_in(request: lawn.Request) {
    if (!request.session.user)
      throw new lawn.Needs_Login()
  }

  addUserToRequest(request: Request): Promise<User | undefined> {
    if (request.user)
      return Promise.resolve(request.user)

    return this.userManager.getUser(request.session.user)
      .then(user => {
        if (user)
          return request.user = sanitize(user)
        else
          return undefined
      })
  }

  loadValidationHelpers(ajv: any) {
    ajv.addSchema(require('./validation/helpers.json'))
  }

  fieldExists(request: Request, fieldOptions: string[]) {
    const keyName = request.data.key
    const value = request.data.value
    if (fieldOptions.indexOf(keyName) == -1)
      throw new Bad_Request(
        'Invalid user field',
        {
          key: 'invalid-user-field',
          data: {field: keyName}
        }
      )

    return this.userManager.fieldExists(keyName, value)
      .then(result => ({
        exists: result
      }))
  }
}

export class User_Service extends UserService {
  constructor(app: express.Application, UserManager: UserManager, settings: ServiceSettings) {
    super(app, UserManager, settings)
  }
}
