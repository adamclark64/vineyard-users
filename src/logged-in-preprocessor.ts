import {Request, Bad_Request, Request_Processor, Version, VersionPreprocessor} from 'vineyard-lawn'
import {UserService} from "./user-service";

export class LoggedInPreprocessor extends VersionPreprocessor {

  constructor(versions: Version []) {
    super(versions)
  }

  createAnonymous(): Request_Processor {
    return (request: Request) => this.common(request)
  }

  createAuthorized(userService: UserService): Request_Processor {
    return request => this.common(request)
      .then(request => {
        userService.require_logged_in(request)
        return request
      })
  }
}
