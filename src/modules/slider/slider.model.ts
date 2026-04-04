import { Schema, model, Document } from "mongoose";
import { ISlider } from "./slider.interface";

const sliderSchema = new Schema<ISlider & Document>(
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
        images: [
            {
                url: {
                    type: String,
                    required: true
                },
                publicId: {
                    type: String,
                    required: true
                }
            }
        ],
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

sliderSchema.index({ displayOrder: 1 });
sliderSchema.index({ isActive: 1, displayOrder: 1 });

const Slider = model<ISlider>("Slider", sliderSchema);
export default Slider;