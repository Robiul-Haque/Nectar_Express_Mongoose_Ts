import { Schema, model } from "mongoose";
import { IReview } from "./review.interface";

const reviewSchema = new Schema<IReview>(
    {
        product: {
            type: Schema.Types.ObjectId,
            ref: "Product",
            required: true,
            index: true
        },
        user: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        rating: {
            type: Number,
            required: true,
            min: 1,
            max: 5
        },
        comment: {
            type: String,
            trim: true,
            maxlength: 1000
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

reviewSchema.index({ product: 1, user: 1 }, { unique: true });

const Review = model<IReview>("Review", reviewSchema);
export default Review;