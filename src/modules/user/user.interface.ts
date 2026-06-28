import { Model, HydratedDocument } from "mongoose";

export type AuthProvider = "email" | "google" | "facebook";
export type UserRole = "user" | "admin" | "driver";
export type DevicePlatform = "android" | "ios" | "web";
export type LoginEventType = "login_success" | "login_failed" | "password_changed" | "otp_verified" | "account_locked" | "account_unlocked" | "logout";

export interface IDevice {
    token: string;
    platform: DevicePlatform;
    deviceId?: string | null;
    deviceModel?: string | null;
    osVersion?: string | null;
    appVersion?: string | null;
    lastActive?: Date;
}

export interface IUser {
    name: string;
    email: string;
    password?: string;
    provider: AuthProvider;
    device: IDevice[] | null;
    notificationEnabled: boolean;
    role: UserRole;
    avatar?: {
        url: string;
        publicId: string;
    };
    location?: {
        latitude: Number;
        longitude: Number;
        country: String;
        city: String;
    };
    isActive: boolean;
    isVerified: boolean;
    otp?: string;
    otpExpires?: Date;
    refreshTokenVersion: number;
    lastLoginAt?: Date;
    createdAt?: Date;
    updatedAt?: Date;

    // ─── Security & Brute-Force Protection ───────────────────────────
    /** Number of consecutive failed login attempts */
    failedLoginCount: number;
    /** If set, the account is locked until this timestamp */
    loginLockedUntil?: Date | null;
    /** Timestamp of last password change (for audit trail) */
    passwordChangedAt?: Date | null;
    /** Last known public IP address */
    lastKnownIp?: string | null;
    /** Last app version reported by the mobile client */
    appVersion?: string | null;
}

export interface IUserMethods {
    comparePassword(candidatePassword: string): Promise<boolean>;
}

export type UserDocument = HydratedDocument<IUser, IUserMethods>;
export type UserModel = Model<IUser, {}, IUserMethods>;