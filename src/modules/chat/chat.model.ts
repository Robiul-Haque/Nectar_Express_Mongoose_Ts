import mongoose, { Schema } from "mongoose";
import { IChat } from "./chat.interface";

const ChatSchema = new Schema<IChat>(
    {
        participants: {
            type: [Schema.Types.ObjectId],
            ref: "User",
            required: true,
            validate: {
                validator: (val: mongoose.Types.ObjectId[]) => val.length === 2,
                message: "Chat must have exactly 2 participants"
            }
        },
        lastMessage: String,
        lastUpdated: {
            type: Date,
            default: Date.now,
            index: true
        },
        status: {
            type: String,
            enum: ["open", "resolved"],
            default: "open",
            index: true
        },
        chatType: {
            type: String,
            enum: ["customer_support", "driver_support", "direct"],
            default: "customer_support",
            index: true
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

ChatSchema.index({ participants: 1 });
ChatSchema.index({ lastUpdated: -1 });
ChatSchema.index({ chatType: 1, status: 1, lastUpdated: -1 });

const Chat = mongoose.model<IChat>("Chat", ChatSchema);
export default Chat;