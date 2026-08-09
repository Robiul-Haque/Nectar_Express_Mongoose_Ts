import { Types } from "mongoose";

export interface IChat {
    participants: Types.ObjectId[];
    lastMessage?: string;
    lastUpdated?: Date;
    status?: "open" | "resolved";
    chatType?: "customer_support" | "driver_support" | "direct";
    createdAt?: Date;
    updatedAt?: Date;
}