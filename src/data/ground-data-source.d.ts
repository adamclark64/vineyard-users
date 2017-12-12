import { UserDataSource } from "./types";
import { Collection } from "vineyard-ground";
import { UserWithPassword } from "../User";
import { EmailVerification, Onetimecode, TempPassword } from "../user-manager";
import { Identity, Settings } from "../types";
export declare class GroundDataSource implements UserDataSource {
    private userModel;
    private sessionCollection;
    private tempPasswordCollection;
    private emailVerificationCollection;
    private oneTimeCodeCollection;
    constructor(settings: Settings);
    getUserModel(): Collection<UserWithPassword>;
    usesRoles(): boolean;
    createUser(newUser: any): Promise<any>;
    getUser(id: string): Promise<UserWithPassword | any>;
    getUserByFilter(filter: any): Promise<UserWithPassword | any>;
    getSessionCollection(): Collection<any>;
    getTempPasswordCollection(): Collection<TempPassword>;
    getOneTimeCodeCollection(): Collection<Onetimecode>;
    getTempPassword(user: Identity): Promise<TempPassword | any>;
    removeTempPassword(tempPassword: Identity): Promise<void>;
    createTempPassword(newTempPassword: any): Promise<TempPassword>;
    createEmailCode(newEmailCode: any): Promise<EmailVerification>;
    getEmailCode(user: Identity): Promise<EmailVerification | any>;
    getOneTimeCode(user: Identity): Promise<Onetimecode | any>;
    updateOneTimeCode(oneTimeCode: Onetimecode, fields: any): Promise<Onetimecode>;
}
