import { UserWithPassword, BaseUser } from "./User";
import { UserDataSource } from "./data";
import { Settings } from "./types";
import { Collection } from "vineyard-ground";
export interface TempPassword {
    user: string;
    password: string;
    created: any;
}
export interface EmailVerification {
    user: string;
    code: string;
}
export interface Onetimecode {
    id: string;
    user: string;
    code: string;
    available: boolean;
}
export declare class UserManager {
    dataSource: UserDataSource;
    constructor(dataSource: UserDataSource | any, settings?: Settings);
    getUserModel(): Collection<UserWithPassword>;
    /**
     * Hashes a password using bcrypt.
     *
     * @param password  Plain text password
     *
     */
    hashPassword(password: string): Promise<string>;
    /**
     * Prepares a new user structure before being saved to the database.
     * Hashes the password, ensures the email is lowercase, and ensures the user.roles is at least an empty array.
     * This function is called by UserManager.createUser and rarely needs to be called directly.
     *
     * @param userFields  Initial user object
     *
     */
    prepareNewUser(userFields: any): Promise<any>;
    /**
     * Saves a new user record to the database.
     * Hashes the password, ensures the email is lowercase, and ensures the user.roles is at least an empty array.
     *
     * @param userFields  Initial user object
     *
     * @param uniqueFields  An array of user field names that must be unique.
     *
     */
    createUser(userFields: any, uniqueFields?: string | string[]): Promise<any>;
    /**
     * Fetches a user from the database.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param id  User identity string or object
     *
     */
    getUser(id: {
        id: string;
    } | string): Promise<UserWithPassword | undefined>;
    getUserByFilter(filter: any): Promise<UserWithPassword | undefined>;
    getSessionCollection(): Collection<any>;
    getUserCollection(): Collection<any>;
    getOneTimeCodeCollection(): Collection<Onetimecode>;
    private tempPasswordHasExpired(tempPassword);
    private emailCodeHasExpired(emailCode);
    matchTempPassword(user: BaseUser, password: string): Promise<boolean>;
    /**
     * Finds a user that has a particular username.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param username  The value to search for
     *
     */
    getUserFromUsername(username: string): Promise<UserWithPassword>;
    /**
     * Finds a user that has a particular email address.
     * This function does not sanitize its result so it can return records with login info.
     *
     * @param email  The value to search for
     *
     */
    getUserFromEmail(email: string): Promise<UserWithPassword>;
    private _createTempPassword(user);
    createTempPassword(username: string | BaseUser): Promise<any>;
    createEmailCode(user: BaseUser): Promise<any>;
    verifyEmailCode(userId: string, submittedCode: string): Promise<boolean>;
    getEmailCode(user: BaseUser): Promise<EmailVerification | undefined>;
    getTempPassword(user: BaseUser): Promise<TempPassword | undefined>;
    getUserOneTimeCode(user: BaseUser): Promise<Onetimecode | undefined>;
    fieldExists(key: string, value: any): Promise<boolean>;
    compareOneTimeCode(oneTimeCode: string, codeRecord: Onetimecode): Promise<boolean>;
    setOneTimeCodeToUnavailable(oneTimeCode: Onetimecode): Promise<Onetimecode>;
    checkUniqueness(user: BaseUser, field?: string): Promise<void>;
    getTempPasswordCollection(): Collection<TempPassword>;
}
