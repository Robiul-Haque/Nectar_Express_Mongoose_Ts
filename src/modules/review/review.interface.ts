import { Types } from "mongoose";

export interface IReview {
    product: Types.ObjectId;
    user: Types.ObjectId;
    rating: number;
    comment?: string;
    createdAt?: Date;
    updatedAt?: Date;
}