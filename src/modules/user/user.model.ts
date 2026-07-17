import { Schema, model, Document } from "mongoose";
import bcrypt from "bcrypt";
import { IUser, IUserMethods, UserModel } from "./user.interface";
import { env } from "../../config/env";

const deviceSchema = new Schema(
    {
        token: {
            type: String,
            required: true
        },
        platform: {
            type: String,
            enum: ["android", "ios", "web"],
            required: true
        },
        deviceId: {
            type: String,
            default: null
        },
        deviceModel: {
            type: String,
            default: null
        },
        osVersion: {
            type: String,
            default: null
        },
        appVersion: {
            type: String,
            default: null
        },
        lastActive: {
            type: Date,
            default: Date.now
        }
    },
    { _id: false }
);

const userSchema = new Schema<IUser, UserModel, IUserMethods>(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            minlength: 2,
            maxlength: 50
        },
        email: {
            type: String,
            required: true,
            lowercase: true,
            trim: true,
            index: true
        },
        password: {
            type: String,
            select: false
        },
        provider: {
            type: String,
            enum: ["email", "google", "facebook"],
            required: true,
            index: true
        },
        device: {
            type: [deviceSchema],
            default: [],
            select: false
        },
        notificationEnabled: {
            type: Boolean,
            default: true,
            index: true
        },
        role: {
            type: String,
            enum: ["user", "admin", "driver"],
            default: "user",
            index: true
        },
        avatar: {
            url: {
                type: String,
                default: null
            },
            publicId: {
                type: String,
                default: null
            }
        },
        location: {
            latitude: { type: Number, default: 0 },
            longitude: { type: Number, default: 0 },
            country: { type: String, default: "" },
            city: { type: String, default: "" }
        },
        isActive: {
            type: Boolean,
            default: true,
            index: true
        },
        isVerified: {
            type: Boolean,
            default: false,
            index: true
        },
        otp: {
            type: String,
            select: false
        },
        otpExpires: {
            type: Date,
            select: false
        },
        refreshTokenVersion: {
            type: Number,
            default: 0
        },
        lastLoginAt: {
            type: Date
        },

        // ─── Security & Brute-Force Protection ───────────────────────────────
        failedLoginCount: {
            type: Number,
            default: 0,
            min: 0
        },
        loginLockedUntil: {
            type: Date,
            default: null,
            index: true   // admin queries for locked accounts
        },
        passwordChangedAt: {
            type: Date,
            default: null
        },
        lastKnownIp: {
            type: String,
            default: null,
            select: false
        },
        appVersion: {
            type: String,
            default: null
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);


userSchema.index({ email: 1, provider: 1 }, { unique: true });
userSchema.index({ "device.token": 1 });

userSchema.pre("save", async function (this: Document & IUser) {
    if (!this.isModified("password") || !this.password) return;

    const salt = await bcrypt.genSalt(env.SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
};

const User = model<IUser, UserModel>("User", userSchema);
export default User;