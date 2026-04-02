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
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

ChatSchema.index({ participants: 1 });
ChatSchema.index({ lastUpdated: -1 });

const Chat = mongoose.model<IChat>("Chat", ChatSchema);
export default Chat;