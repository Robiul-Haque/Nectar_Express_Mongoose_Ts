import { Schema, model, Document } from "mongoose";
import { ISlider, IImage } from "./slider.interface";

const imageSchema = new Schema<IImage>({
    url: {
        type: String,
        required: true,
        trim: true
    },
    publicId: {
        type: String,
        required: true,
        trim: true
    },
    displayOrder: {
        type: Number,
        default: 0,
        min: 0
    }
});

const sliderSchema = new Schema<ISlider & Document>({
    title: {
        type: String,
        required: true,
        trim: true,
        maxlength: 200
    },
    images: {
        type: [imageSchema],
        validate: {
            validator: (val: IImage[]) => val.length >= 1,
            message: "At least one image is required"
        }
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
    animationType: {
        type: String,
        enum: ["fade", "slide", "zoom", "none"],
        default: "fade"
    },
    isActive: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true,
    versionKey: false
});

sliderSchema.index({ isActive: 1 });

const Slider = model<ISlider>("Slider", sliderSchema);
export default Slider;