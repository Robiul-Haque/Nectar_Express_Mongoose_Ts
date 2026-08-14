import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import status from "http-status";
import sendResponse from "../../utils/sendResponse";
import Chat from "../chat/chat.model";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import Message from "./message.model";

export const sendMessage = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;
    const { chatId, content, type = "text", imageBase64, image: imageField } = req.body;
    const fileBuffer = req.file?.buffer;

    const chat = await Chat.findById(chatId);
    if (!chat) return sendResponse(res, 404, "Chat not found");
    if (userRole !== "admin" && !chat.participants.some(p => p.toString() === userId)) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    let imageData = null;

    if (type === "image") {
        if (fileBuffer) {
            const upload = await uploadImageStream(fileBuffer, { folder: "chat_messages" });
            imageData = { url: upload.secure_url, publicId: upload.public_id };
        } else if (imageBase64 || (typeof imageField === "string" && imageField.length > 50)) {
            const rawBase64 = imageBase64 || imageField;
            const cleanBase64 = rawBase64.replace(/^data:image\/\w+;base64,/, "");
            const buffer = Buffer.from(cleanBase64, "base64");
            const upload = await uploadImageStream(buffer, { folder: "chat_messages" });
            imageData = { url: upload.secure_url, publicId: upload.public_id };
        } else {
            return sendResponse(res, status.BAD_REQUEST, "Image file or base64 data required");
        }
    }

    if (type === "text" && !content?.trim()) return sendResponse(res, status.BAD_REQUEST, "Text content cannot be empty");

    const message = await Message.create({
        chatId,
        sender: userId,
        content: type === "text" ? content.trim() : (content?.trim() || "📷 Image"),
        type,
        image: imageData,
        readBy: [userId]
    });

    await Chat.findByIdAndUpdate(chatId, { lastMessage: message.content, lastUpdated: new Date() });

    // Populate sender with user data
    const populatedMessage = await message.populate({
        path: "sender",
        select: "name email role avatar"
    });

    // Transform avatar to only URL
    const transformedMessage = {
        ...populatedMessage.toObject(),
        sender: {
            ...populatedMessage.sender,
            avatar: (populatedMessage.sender as any).avatar?.url || null
        }
    };

    const io = req.app.get("io");
    const chatIdStr = chatId.toString();
    io?.to(chatIdStr).emit("newMessage", transformedMessage);
    io?.to(chatIdStr).emit("message:new", transformedMessage);

    chat.participants.forEach((p: any) => {
        io?.to(p.toString()).emit("newMessage", transformedMessage);
        io?.to(p.toString()).emit("message:new", transformedMessage);
    });

    return sendResponse(res, status.OK, "Message sent", null, transformedMessage);
});

export const getChatMessages = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;
    const { chatId } = req.params;

    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 20, 50);

    const chat = await Chat.findById(chatId);
    if (!chat) return sendResponse(res, 404, "Chat not found");

    if (userRole !== "admin" && !chat.participants.some(p => p.toString() === userId)) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    const messages = await Message.find({ chatId }).populate("sender", "name email role avatar").sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);
    const total = await Message.countDocuments({ chatId });

    // Transform messages to only return avatar URL
    const transformedMessages = messages.map(msg => {
        const msgObj = msg.toObject();
        return {
            ...msgObj,
            sender: {
                ...msgObj.sender,
                avatar: (msgObj.sender as any).avatar?.url || null
            }
        };
    });

    return sendResponse(res, status.OK, "Messages fetched", { page, limit, total }, transformedMessages);
});

export const deleteMessageAdmin = catchAsync(async (req: Request, res: Response) => {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);
    if (!message) return sendResponse(res, status.NOT_FOUND, "Message not found");

    if (message.image?.publicId) {
        try {
            await deleteImage(message.image.publicId);
        } catch (e) {
            console.error("Cloudinary delete error:", e);
        }
    }

    const chatIdStr = message.chatId.toString();
    await Message.findByIdAndDelete(messageId);

    // Update chat's lastMessage in MongoDB to the latest remaining message
    const latestMsg = await Message.findOne({ chatId: message.chatId }).sort({ createdAt: -1 });
    await Chat.findByIdAndUpdate(message.chatId, {
        lastMessage: latestMsg ? latestMsg.content : "No messages yet",
        lastUpdated: latestMsg ? latestMsg.createdAt : new Date()
    });

    const io = req.app.get("io");
    io?.to(chatIdStr).emit("messageDeleted", { messageId, chatId: chatIdStr });
    io?.to(chatIdStr).emit("message:deleted", { messageId, chatId: chatIdStr });

    const chat = await Chat.findById(message.chatId);
    if (chat && chat.participants) {
        chat.participants.forEach((p: any) => {
            io?.to(p.toString()).emit("messageDeleted", { messageId, chatId: chatIdStr });
            io?.to(p.toString()).emit("message:deleted", { messageId, chatId: chatIdStr });
        });
    }

    return sendResponse(res, status.OK, "Message permanently deleted", { messageId });
});

export const markAsRead = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId } = req.params;

    await Message.updateMany({ chatId, readBy: { $ne: userId } }, { $addToSet: { readBy: userId } });

    return sendResponse(res, status.OK, "Marked as read");
});
