import { Schema, model, Document } from "mongoose";
import bcrypt from "bcrypt";
import { IUser, IUserMethods, UserModel } from "./user.interface";

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
        devices: {
            type: [deviceSchema],
            default: [],
            select: false
        },
        role: {
            type: String,
            enum: ["user", "admin"],
            default: "user",
            index: true
        },
        avatar: {
            type: String,
            default: ""
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
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);


userSchema.index({ email: 1, provider: 1 }, { unique: true });
userSchema.index({ "devices.token": 1 });

userSchema.pre("save", async function (this: Document & IUser) {
    if (!this.isModified("password") || !this.password) return;

    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
};

const User = model<IUser, UserModel>("User", userSchema);
export default User;