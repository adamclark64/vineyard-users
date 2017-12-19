"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const vineyard_lawn_1 = require("vineyard-lawn");
class LoggedInPreprocessor extends vineyard_lawn_1.VersionPreprocessor {
    constructor(versions) {
        super(versions);
    }
    createAnonymous() {
        return (request) => this.common(request);
    }
    createAuthorized(userService) {
        return request => this.common(request)
            .then(request => {
            userService.require_logged_in(request);
            return request;
        });
    }
}
exports.LoggedInPreprocessor = LoggedInPreprocessor;
//# sourceMappingURL=logged-in-preprocessor.js.map