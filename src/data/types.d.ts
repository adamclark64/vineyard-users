import { UserWithPassword } from "../User";
import { Collection } from "vineyard-ground";
import { EmailVerification, Onetimecode, TempPassword } from "../user-manager";
import { Identity } from "../types";
export interface UserDataSource {
    getUserModel(): Collection<UserWithPassword>;
    usesRoles(): boolean;
    createUser(newUser: any): Promise<any>;
    getUser(id: string): Promise<UserWithPassword | undefined>;
    getUserByFilter(filter: any): Promise<UserWithPassword | undefined>;
    getSessionCollection(): Collection<any>;
    getTempPasswordCollection(): Collection<TempPassword>;
    getOneTimeCodeCollection(): Collection<Onetimecode>;
    getTempPassword(user: Identity): Promise<TempPassword | undefined>;
    removeTempPassword(tempPassword: Identity): Promise<void>;
    createTempPassword(newTempPassword: any): Promise<TempPassword>;
    createEmailCode(newEmailCode: any): Promise<EmailVerification>;
    getEmailCode(user: Identity): Promise<EmailVerification | undefined>;
    getOneTimeCode(user: Identity): Promise<Onetimecode | undefined>;
    updateOneTimeCode(oneTimeCode: Onetimecode, fields: any): Promise<Onetimecode>;
}
