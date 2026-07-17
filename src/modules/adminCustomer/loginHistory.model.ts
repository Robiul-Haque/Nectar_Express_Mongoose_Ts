import { Schema, model, Types } from "mongoose";
import { LoginEventType } from "../user/user.interface";

export interface ILoginHistory {
    userId: Types.ObjectId;
    event: LoginEventType;
    provider: "email" | "google" | "facebook" | "unknown";
    ip: string;
    userAgent: string;
    platform: "android" | "ios" | "web" | "unknown";
    deviceId?: string | null;
    appVersion?: string | null;
    meta?: Record<string, unknown>;
    createdAt?: Date;
}

const loginHistorySchema = new Schema<ILoginHistory>(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        event: {
            type: String,
            enum: ["login_success", "login_failed", "password_changed", "otp_verified", "account_locked", "account_unlocked", "logout"],
            required: true,
            index: true
        },
        provider: {
            type: String,
            enum: ["email", "google", "facebook", "unknown"],
            default: "unknown"
        },
        ip: {
            type: String,
            default: "unknown"
        },
        userAgent: {
            type: String,
            default: "unknown"
        },
        platform: {
            type: String,
            enum: ["android", "ios", "web", "unknown"],
            default: "unknown"
        },
        deviceId: {
            type: String,
            default: null
        },
        appVersion: {
            type: String,
            default: null
        },
        meta: {
            type: Schema.Types.Mixed,
            default: null
        }
    },
    {
        timestamps: { createdAt: true, updatedAt: false },
        versionKey: false
    }
);

// Compound index for efficient per-user history queries (sorted by newest first)
loginHistorySchema.index({ userId: 1, createdAt: -1 });
loginHistorySchema.index({ userId: 1, event: 1, createdAt: -1 });

// TTL index: auto-delete login history older than 90 days (7,776,000 seconds)
loginHistorySchema.index({ createdAt: 1 }, { expireAfterSeconds: 7_776_000, name: "ttl_90days" });

const LoginHistory = model<ILoginHistory>("LoginHistory", loginHistorySchema);
export default LoginHistory;
