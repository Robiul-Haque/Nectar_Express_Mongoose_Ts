import { Schema, model } from "mongoose";
import { IBrand } from "./brand.interface";

const brandSchema = new Schema<IBrand>(
    {
        name: {
            type: String,
            required: [true, "Brand name is required"],
            trim: true,
            maxlength: [100, "Name cannot exceed 100 characters"],
        },
        slug: {
            type: String,
            required: [true, "Slug is required"],
            unique: true,
            lowercase: true,
            trim: true,
        },
        logo: String,
        isActive: {
            type: Boolean,
            default: true,
        },
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

brandSchema.index({ isActive: 1 });
brandSchema.index({ name: "text" });

export const Brand = model<IBrand>("Brand", brandSchema);