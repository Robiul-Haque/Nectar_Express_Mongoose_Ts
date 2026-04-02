import mongoose, { Schema } from "mongoose";

const MessageSchema = new Schema(
    {
        chatId: {
            type: Schema.Types.ObjectId,
            ref: "Chat",
            required: true,
            index: true
        },
        sender: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        content: String,
        type: {
            type: String,
            enum: ["text", "image"],
            default: "text"
        },
        image: {
            url: String,
            publicId: String
        },
        readBy: [{
            type: Schema.Types.ObjectId,
            ref: "User"
        }]
    },
    {
        timestamps: true,
        versionKey: false
    }
);

MessageSchema.index({ chatId: 1, createdAt: -1 });

const Message = mongoose.model("Message", MessageSchema);
export default Message;