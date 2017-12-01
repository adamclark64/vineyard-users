/// <reference types="sequelize" />
import * as Sequelize from 'sequelize';
import { Collection } from "vineyard-ground";
import { UserWithPassword, BaseUser } from "./User";
export interface Settings {
    user_model?: any;
    tableKeys?: any;
    model: any;
}
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
    private db;
    private userModel;
    private sessionCollection;
    private tempPasswordCollection;
    private emailVerificationCollection;
    private oneTimeCodeCollection;
    constructor(db: Sequelize.Sequelize, settings: Settings);
    getUserModel(): Collection<UserWithPassword>;
    hashPassword(password: string): Promise<string>;
    prepareNewUser(fields: any): Promise<any>;
    prepare_new_user(fields: any): Promise<any>;
    createUser(fields: any, uniqueField?: string | string[]): Promise<any>;
    getUser(id: {
        id: string;
    } | string): Promise<UserWithPassword | undefined>;
    getSessionCollection(): any;
    getUserCollection(): Collection<UserWithPassword>;
    getOneTimeCodeCollection(): Collection<Onetimecode>;
    private tempPasswordHasExpired(tempPassword);
    private emailCodeHasExpired(emailCode);
    matchTempPassword(user: BaseUser, password: string): Promise<boolean>;
    getUserFromUsername(username: string): Promise<UserWithPassword>;
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
export declare class User_Manager extends UserManager {
    constructor(db: Sequelize.Sequelize, settings: Settings);
}
