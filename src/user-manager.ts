import {promiseEach} from "./utility";
import {UserWithUsername, UserWithPassword, BaseUser} from "./User"
import {BadRequest} from "vineyard-lawn/source/errors";
import {UserDataSource} from "./data";
import {GroundDataSource} from "./data/ground-data-source";
import {Settings} from "./types";
import {Collection} from "vineyard-ground";

const bcrypt = require('bcrypt');

export interface TempPassword {
  user: string
  password: string
  created: any
}

export interface EmailVerification {
  user: string
  code: string
}

export interface Onetimecode {
  id: string
  user: string
  code: string
  available: boolean
}

export class UserManager {
  dataSource: UserDataSource

  constructor(dataSource: UserDataSource | any, settings?: Settings) {
    this.dataSource = this.dataSource || new GroundDataSource(settings as Settings)

    const self: any = this

    // Backwards compatibility
    self.create_user = this.createUser
    self.prepare_new_user = this.prepareNewUser
  }

  getUserModel(): Collection<UserWithPassword> {
    return this.dataSource.getUserModel()
  }

  /**
   * Hashes a password using bcrypt.
   *
   * @param password  Plain text password
   *
   */
  hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10)
  }

  /**
   * Prepares a new user structure before being saved to the database.
   * Hashes the password, ensures the email is lowercase, and ensures the user.roles is at least an empty array.
   * This function is called by UserManager.createUser and rarely needs to be called directly.
   *
   * @param userFields  Initial user object
   *
   */
  prepareNewUser(userFields: any) {
    if (!userFields.roles && (this.userModel as any).trellis.properties.roles)
      userFields.roles = [];

    if (typeof userFields.email === 'string')
      userFields.email = userFields.email.toLowerCase()

    return this.hashPassword(userFields.password)
      .then(salt_and_hash => {
        userFields.password = salt_and_hash;
        return userFields
      })
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
  createUser(userFields: any, uniqueFields: string | string[] = 'username'): Promise<any> {
    const _uniqueFields = Array.isArray(uniqueFields) ? uniqueFields : [uniqueFields]
    return promiseEach(_uniqueFields, (field: any) => this.checkUniqueness(userFields, field))
      .then(() => {
        return this.prepareNewUser(userFields)
          .then(user => this.userModel.create(userFields))
      })
  }

  /**
   * Fetches a user from the database.
   * This function does not sanitize its result so it can return records with login info.
   *
   * @param id  User identity string or object
   *
   */
  getUser(id: { id: string } | string): Promise<UserWithPassword | undefined> {
    return this.userModel.get(id).exec()
  }

  getUserByFilter(filter: any): Promise<UserWithPassword | undefined> {
    return this.userModel.first(filter).exec()
  }

  getSessionCollection() {
    return this.sessionCollection
  }

  getUserCollection() {
    return this.userModel
  }

  getOneTimeCodeCollection() {
    return this.oneTimeCodeCollection
  }

  private tempPasswordHasExpired(tempPassword: TempPassword): boolean {
    const expirationDate = new Date(tempPassword.created.getTime() + (6 * 60 * 60 * 1000))
    return new Date() > expirationDate
  }

  private emailCodeHasExpired(emailCode: { created: Date }): boolean {
    const expirationDate = new Date(emailCode.created.getTime() + (6 * 60 * 60 * 1000))
    return new Date() > expirationDate
  }

  matchTempPassword(user: BaseUser, password: string): Promise<boolean> {
    if (!this.tempPasswordCollection)
      return Promise.resolve(false)

    return this.tempPasswordCollection.first({user: user.id})
      .then((storedTempPass: any) => {
        if (!storedTempPass)
          return false

        if (this.tempPasswordHasExpired(storedTempPass))
          return this.tempPasswordCollection.remove(storedTempPass)
            .then(() => false)

        return bcrypt.compare(password, storedTempPass.password)
          .then((success: boolean) => {
            if (!success)
              return false

            return this.getUserCollection().update(user, {
              password: storedTempPass.password
            })
              .then(() => this.tempPasswordCollection.remove(storedTempPass))
              .then(() => true)
          })
      })
  }

  /**
   * Finds a user that has a particular username.
   * This function does not sanitize its result so it can return records with login info.
   *
   * @param username  The value to search for
   *
   */
  getUserFromUsername(username: string): Promise<UserWithPassword> {
    return this.userModel.first({username: username})
      .then(user => {
        if (!user)
          throw new BadRequest("Invalid username: " + username)

        return user
      })
  }

  /**
   * Finds a user that has a particular email address.
   * This function does not sanitize its result so it can return records with login info.
   *
   * @param email  The value to search for
   *
   */
  getUserFromEmail(email: string): Promise<UserWithPassword> {
    return this.userModel.first({email: email})
      .then(user => {
        if (!user)
          throw new BadRequest("Invalid email: " + email)

        return user
      })
  }

  private _createTempPassword(user: BaseUser): Promise<any> {
    return this.getTempPassword(user)
      .then(tempPassword => {
        if (!tempPassword) {
          const passwordString = Math.random().toString(36).slice(2)
          return this.hashPassword(passwordString)
            .then(hashedPassword => this.tempPasswordCollection.create({
                user: user,
                password: hashedPassword
              })
            )
            .then(() => {
              return {
                password: passwordString,
                username: user.username
              }
            })
        } else {
          return Promise.resolve(undefined)
        }
      })
  }

  createTempPassword(username: string | BaseUser): Promise<any> {
    if (typeof username == 'string') {
      return this.getUserFromUsername(username)
        .then(user => this._createTempPassword(user))
    }
    else {
      return this._createTempPassword(username)
    }
  }

  createEmailCode(user: BaseUser): Promise<any> {
    return this.getEmailCode(user)
      .then(emailCode => {
        if (!emailCode) {
          const newEmlCode = Math.random().toString(36).slice(2)
          return this.emailVerificationCollection.create({
            user: user,
            code: newEmlCode
          })
            .then(() => newEmlCode)
        } else {
          return Promise.resolve(emailCode.code)
        }
      })
  }

  verifyEmailCode(userId: string, submittedCode: string): Promise<boolean> {
    return this.userModel.first({id: userId}).exec()
      .then(user => {
        if (!user)
          return false

        return this.emailVerificationCollection.first({
          user: userId
        })
          .then(emailCode => {
            if (!emailCode || emailCode.code != submittedCode)
              return Promise.resolve(false)

            return this.userModel.update(user, {
              emailVerified: true
            })
            // .then(() => this.emailVerificationCollection.remove(emailCode))
              .then(() => true)
          })
      })
  }

  getEmailCode(user: BaseUser) {
    return this.emailVerificationCollection.first({user: user.id}).exec()
  }

  getTempPassword(user: BaseUser): Promise<TempPassword | undefined> {
    return this.tempPasswordCollection.first({user: user.id}).exec()
  }

  getUserOneTimeCode(user: BaseUser): Promise<Onetimecode | undefined> {
    return this.oneTimeCodeCollection.first({user: user.id, available: true}).exec()
  }

  fieldExists(key: string, value: any): Promise<boolean> {
    const filter: any = {}
    filter[key] = value
    return this.userModel.first(filter).exec()
      .then((user?: BaseUser) => !!user)
  }

  compareOneTimeCode(oneTimeCode: string, codeRecord: Onetimecode): Promise<boolean> {
    return Promise.resolve(oneTimeCode === codeRecord.code)
  }

  setOneTimeCodeToUnavailable(oneTimeCode: Onetimecode) {
    return this.oneTimeCodeCollection.update(oneTimeCode, {available: false})
  }

  checkUniqueness(user: BaseUser, field = 'username') {
    return this.fieldExists(field, user[field])
      .then(result => {
        if (result) {
          throw new Error(`User validation error: ${field} must be unique`)
        }
      })
  }

  getTempPasswordCollection() {
    return this.tempPasswordCollection
  }
}

module.exports.User_Manager = UserManager