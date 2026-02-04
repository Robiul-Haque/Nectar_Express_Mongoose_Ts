import mongoose, { Schema } from 'mongoose';
import { IUser } from './user.interface';

const userSchema: Schema<IUser> = new Schema(
    {
        name: { type: String, required: true },
        email: { type: String, required: true, unique: true },
        password: { type: String },
        role: { type: String, enum: ['admin', 'user'], default: 'user' },
        phone: { type: String, default: '' },
        avatar: { type: String, default: '' },
        provider: { type: String, enum: ['google', 'facebook', 'email'], default: 'email' },
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

export default mongoose.model<IUser>('User', userSchema);