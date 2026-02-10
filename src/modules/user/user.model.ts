import { Schema, model, Document } from "mongoose";
import bcrypt from "bcrypt";
import { IUser, IUserMethods, UserModel } from "./user.interface";

const userSchema = new Schema<IUser, UserModel, IUserMethods>(
    {
        name: {
            type: String,
            required: true,
            trim: true
        },
        email: {
            type: String,
            required: true,
            lowercase: true,
            unique: true,
            index: true,
            trim: true,
        },
        password: {
            type: String,
            select: true,
            trim: true
        },
        provider: {
            type: String,
            enum: ["email", "google", "facebook"],
            required: true
        },
        fcmTokens: {
            type: [String],
            default: [],
            select: false
        },
        role: {
            type: String,
            enum: ["user", "admin"],
            default: "user"
        },
        avatar: {
            type: String,
            default: ""
        },
        isVerified: {
            type: Boolean,
            default: false
        },
        otp: {
            type: String,
            select: false
        },
        otpExpires: Date,
    },
    {
        timestamps: true,
        versionKey: false,
    }
);


userSchema.pre("save", async function (this: Document & IUser & IUserMethods) {
    if (!this.isModified("password") || !this.password) return;
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
    if (!this.password) return false;
    return bcrypt.compare(candidatePassword, this.password);
};

userSchema.index({ email: 1, provider: 1 }, { unique: true });

const User = model<IUser, UserModel>("User", userSchema);
export default User;