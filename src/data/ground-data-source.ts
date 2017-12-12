import {UserDataSource} from "./types"
import {Collection} from "vineyard-ground"
import {UserWithPassword} from "../User"
import {EmailVerification, Onetimecode, TempPassword} from "../user-manager"
import {Identity, Settings} from "../types"

export class GroundDataSource implements UserDataSource {
  private userModel: Collection<UserWithPassword>
  private sessionCollection: any
  private tempPasswordCollection: Collection<TempPassword>
  private emailVerificationCollection: Collection<EmailVerification>
  private oneTimeCodeCollection: Collection<Onetimecode>

  constructor(settings: Settings) {
    if (!settings)
      throw new Error("Missing settings argument.")
    this.userModel = settings.user_model || settings.model.User

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
      })

      const collections = settings.model.ground.collections
      this.sessionCollection = collections.Session
      this.tempPasswordCollection = collections.Session
      this.emailVerificationCollection = collections.EmailVerification
      this.oneTimeCodeCollection = collections.Onetimecode
    }
  }

  getUserModel(): Collection<UserWithPassword> {
    return this.userModel
  }

  usesRoles(): boolean {
    return (this.userModel as any).trellis.properties.roles
  }

  createUser(newUser: any): Promise<any> {
    return this.userModel.create(newUser)
  }

  getUser(id: string): Promise<UserWithPassword | any> {
    return this.userModel.get(id).exec()
  }

  getUserByFilter(filter: any): Promise<UserWithPassword | any> {
    return this.userModel.first(filter).exec()
  }

  getSessionCollection(): Collection<any> {
    return this.sessionCollection
  }

  getTempPasswordCollection(): Collection<TempPassword> {
    return this.tempPasswordCollection
  }

  getOneTimeCodeCollection(): Collection<Onetimecode> {
    return this.oneTimeCodeCollection
  }

  getTempPassword(user: Identity): Promise<TempPassword | any> {
    return this.tempPasswordCollection.first({user: user}).exec()
  }

  removeTempPassword(tempPassword: Identity): Promise<void> {
    return this.tempPasswordCollection.remove(tempPassword)
      .then(() => {
      })
  }

  createTempPassword(newTempPassword: any): Promise<TempPassword> {
    return this.tempPasswordCollection.create(newTempPassword)
  }

  createEmailCode(newEmailCode: any): Promise<EmailVerification> {
    return this.emailVerificationCollection.create(newEmailCode)
  }

  getEmailCode(user: Identity): Promise<EmailVerification | any> {
    return this.emailVerificationCollection.first({user: user}).exec()
  }

  getOneTimeCode(user: Identity): Promise<Onetimecode | any> {
    return null
  }

  updateOneTimeCode(oneTimeCode: Onetimecode, fields: any): Promise<Onetimecode> {
    return null
  }
}