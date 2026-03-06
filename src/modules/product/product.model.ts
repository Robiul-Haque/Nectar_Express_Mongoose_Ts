import { Schema, model, Types } from "mongoose";
import { IProduct } from "./product.interface";

const productSchema = new Schema<IProduct>(
    {
        name: {
            type: String,
            required: true,
            trim: true,
            maxlength: 150
        },
        slug: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            index: true
        },
        description: {
            type: String,
            trim: true,
            maxlength: 2000
        },
        measurement: {
            value: {
                type: Number,
                required: true,
                min: 0
            },
            unit: {
                type: String,
                required: true,
                enum: ["kg", "g", "pc"]
            }
        },
        price: {
            type: Number,
            required: true,
            min: 0
        },
        discountPrice: {
            type: Number,
            min: 0,
            validate: {
                validator: function (this: any, value: number) {
                    if (!value) return true;
                    return value < this.price;
                },
                message: "Discount price must be less than original price"
            }
        },
        stock: {
            type: Number,
            required: true,
            min: 0,
            default: 0
        },
        images: {
            url: {
                type: String,
                required: true
            },
            publicId: {
                type: String,
                required: true
            }
        },
        category: {
            type: Types.ObjectId,
            ref: "Category",
            required: true,
            index: true
        },
        brand: {
            type: Types.ObjectId,
            ref: "Brand",
            required: true,
            index: true
        },
        nutrition: {
            type: String,
            trim: true,
            maxlength: 1000
        },
        averageRating: {
            type: Number,
            default: 0,
            min: 0,
            max: 5
        },
        totalReviews: {
            type: Number,
            default: 0
        },
        isFeatured: {
            type: Boolean,
            default: false,
            index: true
        },
        isActive: {
            type: Boolean,
            default: true,
            index: true
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

productSchema.index({ name: "text", description: "text" });
productSchema.index({ category: 1, isActive: 1 });
productSchema.index({ price: 1 });

export const Product = model<IProduct>("Product", productSchema);