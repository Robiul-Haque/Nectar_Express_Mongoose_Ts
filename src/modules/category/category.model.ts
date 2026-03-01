import { Schema, model } from "mongoose";
import { ICategory } from "./category.interface";

const categorySchema = new Schema<ICategory>(
    {
        name: {
            type: String,
            required: [true, "Category name is required"],
            trim: true,
            maxlength: [100, "Name cannot exceed 100 characters"],
        },
        description: {
            type: String,
            trim: true,
            maxlength: [500, "Description cannot exceed 500 characters"],
        },
        icon: {
            url: {
                type: String,
                default: null
            },
            publicId: {
                type: String,
                default: null
            }
        },
        level: {
            type: Number,
            default: 0
        },
        parent: {
            type: Schema.Types.ObjectId,
            ref: "Category",
            default: null,
        },
        isActive: {
            type: Boolean,
            default: true,
        },
        isFeatured: {
            type: Boolean,
            default: false,
        },
        sortOrder: {
            type: Number,
            default: 0,
        },
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

categorySchema.index({ isActive: 1, parent: 1 });
categorySchema.index({ name: "text" });

export const Category = model<ICategory>("Category", categorySchema);