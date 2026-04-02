import { Types } from "mongoose";

export type TMessageType = "text" | "image";

export interface IMessage {
    _id?: Types.ObjectId;
    chatId: Types.ObjectId;
    sender: Types.ObjectId;
    content?: string;
    type: TMessageType;
    image?: {
        url?: string;
        publicId?: string;
    };
    readBy: Types.ObjectId[];
    createdAt?: Date;
    updatedAt?: Date;
}