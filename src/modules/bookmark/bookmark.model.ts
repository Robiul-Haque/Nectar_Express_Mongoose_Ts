import mongoose, { Schema } from "mongoose";
import { IBookmark } from "./bookmark.interface";

const bookmarkSchema = new Schema<IBookmark>(
    {
        user: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        product: {
            type: Schema.Types.ObjectId,
            ref: "Product",
            required: true,
            index: true
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

bookmarkSchema.index({ user: 1, product: 1 }, { unique: true });

const Bookmark = mongoose.model<IBookmark>("Bookmark", bookmarkSchema);
export default Bookmark;