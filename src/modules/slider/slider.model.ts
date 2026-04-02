import { Schema, model, Document } from "mongoose";
import { ISliderItem } from "./slider.interface";

const sliderItemSchema = new Schema<ISliderItem & Document>(
    {
        title: {
            type: String,
            required: true,
            trim: true,
            maxlength: 200
        },
        description: {
            type: String,
            trim: true,
            maxlength: 500
        },
        image: {
            url: {
                type: String,
                required: true
            },
            publicId: {
                type: String,
                required: true
            },
        },
        actionButton: {
            text: {
                type: String,
                trim: true,
                maxlength: 50
            },
            link: {
                type: String,
                trim: true
            }
        },
        displayOrder: {
            type: Number,
            required: true,
            default: 0
        },
        animationType: {
            type: String,
            enum: ["fade", "slide", "zoom", "none"],
            default: "fade"
        },
        isActive: {
            type: Boolean,
            default: true
        },
    },
    {
        timestamps: true,
        versionKey: false
    }
);

sliderItemSchema.index({ displayOrder: 1 });
sliderItemSchema.index({ isActive: 1, displayOrder: 1 });

export const SliderItem = model<ISliderItem>("SliderItem", sliderItemSchema);