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
        logo: {
            url: {
                type: String,
                default: null
            },
            publicId: {
                type: String,
                default: null,
            }
        },
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

brandSchema.index({ isActive: 1, name: 1 });
brandSchema.index({ name: "text" });

export const Brand = model<IBrand>("Brand", brandSchema);