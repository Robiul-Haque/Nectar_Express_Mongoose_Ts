import mongoose, { Schema } from "mongoose";
import { IChat, IMessage } from "./chat.interface";

const MessageSchema = new Schema<IMessage>(
    {
        sender: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        content: {
            type: String,
            trim: true
        },
        type: {
            type: String,
            enum: ["text", "image"],
            default: "text"
        },
        timestamp: {
            type: Date,
            default: Date.now,
            index: true
        },
        read: {
            type: Boolean,
            default: false,
            index: true
        },
        image: {
            url: {
                type: String,
                default: null
            },
            publicId: {
                type: String,
                default: null
            }
        }
    },
    {
        _id: true,
        versionKey: false
    }
);

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
        messages: {
            type: [MessageSchema],
            default: []
        },
        lastMessage: {
            type: String,
            default: ""
        },
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
ChatSchema.index({ "messages.timestamp": -1 });

const Chat = mongoose.model<IChat>("Chat", ChatSchema);
export default Chat;