import { Types } from "mongoose";

export interface IChat {
    participants: Types.ObjectId[];
    lastMessage?: string;
    lastUpdated?: Date;
    createdAt?: Date;
    updatedAt?: Date;
}