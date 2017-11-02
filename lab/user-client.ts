import {WebClient} from "vineyard-lawn/lab"
import {getTwoFactorToken} from "../src"

export type UserIdentifier = { email: string } | { username: string } | { id: string }

export type CreateUserData  =  UserIdentifier  &  {
  password: string,
  twoFactorSecret?: string
}

export class UserClient<CreateUserResponse> {
  private webClient: WebClient;
  private createUserResponse: CreateUserResponse;
  private password: string;
  private twoFactorSecret: string;
  private userIdentifier: UserIdentifier;

  constructor(webClient: WebClient) {
    this.webClient = webClient;
  }

  prepareTwoFactor(): Promise<string> {
    return this.webClient.get('user/2fa')
      .then((data:any) => this.webClient.post('user/2fa', {
          twoFactor: getTwoFactorToken(data.secret)
        })
          .then(() => this.twoFactorSecret = data.secret)
      )
  }

  register(createUser: CreateUserData): Promise<CreateUserResponse> {
    this.userIdentifier = createUser;

    this.password = createUser.password;
    return this.prepareTwoFactor()
      .then(twoFactorSecret => {
        createUser.twoFactorSecret = twoFactorSecret
        return this.webClient.post('user', createUser)
      })
      .then(user => {
        this.createUserResponse = <CreateUserResponse> user;
        return this.createUserResponse;
      })
  }

  login(): Promise<void> {
      return this.webClient.post('user/login', Object.assign({
          password: this.password,
          twoFactor: getTwoFactorToken(this.twoFactorSecret)
      }), this.userIdentifier)
  }

  loginWithUsername(): Promise<void> {
    const userIdentifier = <{ username: string }> this.userIdentifier;
    return this.webClient.post('user/login', {
      username: userIdentifier.username,
      password: this.password,
      twoFactor: getTwoFactorToken(this.twoFactorSecret)
    })
  }

  loginWithEmail(): Promise<void> {
    const userIdentifier = <{ email: string }> this.userIdentifier;
    return this.webClient.post('user/login', {
      email: userIdentifier.email,
      password: this.password,
      twoFactor: getTwoFactorToken(this.twoFactorSecret)
    })
  }

  logout(): Promise<void> {
    return this.webClient.post('user/logout')
  }

  getWebClient(): WebClient {
    return this.webClient
  }

  getUserIdentifier(): UserIdentifier {
    return this.userIdentifier
  }

}