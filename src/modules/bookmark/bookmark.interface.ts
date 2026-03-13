import { Types } from "mongoose";

export interface IBookmark extends Document {
    user: Types.ObjectId;
    product: Types.ObjectId;
    createdAt: Date;
    updatedAt: Date;
}