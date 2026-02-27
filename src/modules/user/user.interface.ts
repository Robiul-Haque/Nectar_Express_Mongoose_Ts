import { Model, HydratedDocument } from "mongoose";

export type AuthProvider = "email" | "google" | "facebook";
export type UserRole = "user" | "admin";
export type DevicePlatform = "android" | "ios" | "web";

export interface IDevice {
    token: string;
    platform: DevicePlatform;
    deviceId?: string | null;
    lastActive?: Date;
}

export interface IUser {
    name: string;
    email: string;
    password?: string;
    provider: AuthProvider;
    devices: IDevice[];
    role: UserRole;
    avatar?: {
        url: string;
        publicId: string;
    };
    isVerified: boolean;
    otp?: string;
    otpExpires?: Date;
    refreshTokenVersion: number;
    lastLoginAt?: Date;
    createdAt?: Date;
    updatedAt?: Date;
}

export interface IUserMethods {
    comparePassword(candidatePassword: string): Promise<boolean>;
}

export type UserDocument = HydratedDocument<IUser, IUserMethods>;
export type UserModel = Model<IUser, {}, IUserMethods>;