import { Model } from "mongoose";

export interface IUser {
    name: string;
    email: string;
    password?: string;
    provider: "email" | "google" | "facebook";
    role: "user" | "admin";
    avatar?: string;
    isVerified: boolean;
    otp?: string;
    otpExpires?: Date;
    createdAt?: Date;
    updatedAt?: Date;
}

export interface IUserMethods {
    comparePassword(candidatePassword: string): Promise<boolean>;
}

export type UserModel = Model<IUser, {}, IUserMethods>;