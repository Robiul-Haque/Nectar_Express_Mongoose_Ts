import { Schema, model, Types } from "mongoose";

export interface IAdminNote {
    userId: Types.ObjectId;
    adminId: Types.ObjectId;
    note: string;
    createdAt?: Date;
    updatedAt?: Date;
}

const adminNoteSchema = new Schema<IAdminNote>(
    {
        userId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        adminId: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        note: {
            type: String,
            required: true,
            trim: true,
            maxlength: [2000, "Note cannot exceed 2000 characters"]
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

// Compound index: fetch all notes for a user sorted by newest first
adminNoteSchema.index({ userId: 1, createdAt: -1 });

const AdminNote = model<IAdminNote>("AdminNote", adminNoteSchema);
export default AdminNote;
