import {Onetimecode, UserManager} from "./user-manager";

const session = require('express-session');
import {Bad_Request, Request, BadRequest} from 'vineyard-lawn'
import * as lawn from 'vineyard-lawn'
import * as express from 'express'
import * as two_factor from './two-factor'
import {UserWithUsername, UserWithPassword, BaseUser} from "./User";
import {SequelizeStore} from "./session-store";

const bcrypt = require('bcrypt')

export interface CookieSettings {
  secret: string
  maxAge: number
  rolling?: boolean
  secure: boolean
}

export type Service_Settings = CookieSettings

function sanitize(user: UserWithPassword): BaseUser {
  const result = Object.assign({}, user)
  delete result.password
  delete result.twoFactorSecret
  return result
}

export function createDefaultSessionStore(userManager: UserManager, expiration: number, secure: boolean) {
  return new SequelizeStore(userManager.getSessionCollection().getTableClient().getSequelizeModel(), {
    expiration: expiration,
    updateFrequency: 5 * 60 * 1000,
    secure: secure,
  })
}

// For backwards compatibility
function getTwoFactorEnabled(user: BaseUser): boolean {
  if (typeof user.twoFactorEnabled == 'boolean')
    return user.twoFactorEnabled

  return !!(user as any).two_factor_enabled
}

function getTwoFactorSecret(user: BaseUser): string {
  if (typeof user.twoFactorSecret == 'string')
    return user.twoFactorSecret

  return (user as any).two_factor_secret || ''
}

export class UserService {
  private userManager: UserManager
  private user_manager: UserManager

  constructor(app: express.Application, userManager: UserManager, cookie: CookieSettings,
              sessionStore: any = createDefaultSessionStore(userManager, cookie.maxAge, cookie.secure)) {

    this.userManager = this.user_manager = userManager

    if (!cookie.secret)
      throw new Error("UserService settings.secret cannot be empty.")

    app.use(session({
      secret: cookie.secret,
      store: sessionStore,
      cookie: cookie,
      resave: false,
      saveUninitialized: true
    }))

    // Backwards compatibility
    const self: any = this
    self.login = () => {
      return (request: Request) => this.loginWithUsername(request)
    }

    self.create_login_handler = () => {
      return (request: Request) => this.loginWithUsername(request)
    }

    self.create_login_2fa_handler = () => {
      return (request: Request) => this.checkUsernameOrEmailLogin(request)
        .then(user => {
          this.checkTwoFactor(user, request)
          return this.finishLogin(request, user)
        })
    }

    self.createLogin2faHandlerWithBackup = () => {
      return (request: Request) => this.login2faWithBackup(request)
    }

    self.createLogoutHandler = () => {
      return (request: Request) => this.logout(request)
    }

    self.create_logout_handler = () => {
      return self.createLogoutHandler()
    }
  }

  private _checkLogin(filter: any, password: string) {
    return this.userManager.getUserByFilter(filter)
      .then(user => {
        if (!user)
          throw new Bad_Request('Invalid credentials.', {key: 'invalid-credentials'})

        return bcrypt.compare(password, user.password)
          .then((success: boolean) => success
            ? user
            : this.checkTempPassword(user, password)
          )
      })
  }

  checkTempPassword(user: BaseUser, password: string) {
    return this.userManager.matchTempPassword(user, password)
      .then(success => {
        if (!success)
          throw new Bad_Request('Invalid credentials.', {key: 'invalid-credentials'})

        return user
      })
  }

  /**
   * Compares a plain text password with a salted password.
   *
   * @param password  Plain text password
   *
   * @param hash  Salted password
   *
   */
  checkPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash)
  }

  /**
   * Checks login credentials using a password and a username or email
   *
   * @param request  Vineyard Lawn request
   *
   */
  checkUsernameOrEmailLogin(request: Request): Promise<UserWithPassword> {
    const data = request.data

    const filter = data.username
      ? {username: data.username}
      : {email: data.email}

    return this._checkLogin(filter, data.password)
  }

  checkEmailLogin(request: Request): Promise<UserWithPassword> {
    const data = request.data
    return this._checkLogin({email: data.email}, data.password)
  }

  finishLogin(request: Request, user: UserWithPassword) {
    request.session.user = user.id
    return sanitize(user)
  }

  loginWithUsername(request: Request) {
    return this.checkUsernameOrEmailLogin(request)
      .then(user => this.finishLogin(request, user))
  }

  checkTwoFactor(user: BaseUser, request: Request) {
    if (getTwoFactorEnabled(user) && !two_factor.verifyTwoFactorToken(getTwoFactorSecret(user), request.data.twoFactor))
      throw new Bad_Request('Invalid Two Factor Authentication code.', {key: "invalid-2fa"})
  }

  login2faWithBackup(request: Request) {
    return this.checkUsernameOrEmailLogin(request)
      .then(user => {
        const currentUser = user
        if (getTwoFactorEnabled(user) && !two_factor.verifyTwoFactorToken(getTwoFactorSecret(user), request.data.twoFactor))
          return this.verify2faOneTimeCode(request, currentUser).then(backupCodeCheck => {
            if (!backupCodeCheck)
              throw new Bad_Request('Invalid Two Factor Authentication code.', {key: "invalid-2fa"})
            return this.finishLogin(request, currentUser)
          })
        return this.finishLogin(request, currentUser)
      })
  }

  verify2faOneTimeCode(request: Request, user: BaseUser): Promise<boolean> {
    return this.userManager.getUserOneTimeCode(user).then((code: Onetimecode | undefined) => {
      if (!code) {
        return false
      }
      return this.userManager.compareOneTimeCode(request.data.twoFactor, code).then(pass => {
        if (!pass) {
          return false
        }
        return this.userManager.setOneTimeCodeToUnavailable(<Onetimecode> code)
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

  private async getUser(usernameOrUser: string | BaseUser): Promise<BaseUser | undefined> {
    if (typeof usernameOrUser === 'string')
      return this.userManager.getUserByFilter({username: usernameOrUser})
    else if (typeof usernameOrUser === 'object')
      return Promise.resolve(usernameOrUser)

    else throw new Error("Invalid username or user.")
  }

  async createTempPassword(usernameOrUser: string | BaseUser): Promise<any> {
    const userOrUndefined = await this.getUser(usernameOrUser)
    if (!userOrUndefined)
      return Promise.resolve(new BadRequest("Invalid user"))

    const user = userOrUndefined as BaseUser
    
    return this.userManager.getTempPassword(user)
      .then(tempPassword => {
        if (!tempPassword) {
          const passwordString = Math.random().toString(36).slice(2)
          return this.userManager.hashPassword(passwordString)
            .then(hashedPassword => this.userManager.getTempPasswordCollection().create({
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
  }

  require_logged_in(request: lawn.Request) {
    if (!request.session.user)
      throw new lawn.Needs_Login()
  }

  getSanitizedUser(id: string): Promise<BaseUser> {
    return this.userManager.getUser(id)
      .then(sanitize)
  }

  addUserToRequest(request: Request): Promise<BaseUser | undefined> {
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

  getModel(): UserManager {
    return this.userManager
  }
}

export class User_Service extends UserService {
  constructor(app: express.Application, UserManager: UserManager, settings: CookieSettings) {
    super(app, UserManager, settings)
  }
}
