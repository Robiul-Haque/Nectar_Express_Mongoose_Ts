import { Document, Types } from "mongoose";

export interface IMessage {
    _id?: Types.ObjectId;
    sender: Types.ObjectId;
    content: string;
    type: "text" | "image";
    timestamp: Date;
    read: boolean;
    image?: {
        url: string | null;
        publicId: string | null;
    };
}

export interface IChat extends Document {
    participants: Types.ObjectId[];
    messages: IMessage[];
    lastMessage: string;
    lastUpdated: Date;
    createdAt: Date;
    updatedAt: Date;
}