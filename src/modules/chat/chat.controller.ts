import { Request, Response } from "express";
import mongoose from "mongoose";
import Chat from "./chat.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import status from "http-status";

export const sendMessage = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId, content, type = "text" } = req.body;
    const fileBuffer = req.file?.buffer;

    const chat = await Chat.findById(chatId).select("participants").lean();
    if (!chat) return sendResponse(res, status.NOT_FOUND, "Chat not found");

    const isParticipant = chat.participants.some(p => p.toString() === userId);
    if (!isParticipant) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    const message: any = {
        _id: new mongoose.Types.ObjectId(),
        sender: new mongoose.Types.ObjectId(userId),
        type,
        timestamp: new Date(),
        read: false,
    };

    // text message
    if (type === "text") message.content = content?.trim();

    // image message
    if (type === "image" && fileBuffer) {
        const result = await uploadImageStream(fileBuffer, { folder: "chat_messages" });
        message.image = { url: result.secure_url, publicId: result.public_id };
        if (!message.content) message.content = "Image"; // lastMessage update fallback
    }

    // update chat document
    await Chat.updateOne({ _id: chatId }, { $push: { messages: message }, $set: { lastMessage: message.content, lastUpdated: new Date() } });

    // real-time emit via socket.io
    const io = req.app.get("io");
    io?.to(chatId).emit("newMessage", { ...message, sender: userId });

    return sendResponse(res, status.OK, "Message sent successfully", message);
});

export const getChatMessages = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId } = req.params;

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 20;

    const chat = await Chat.findById(chatId).select("participants messages").populate("messages.sender", "name email role").lean();
    if (!chat) return sendResponse(res, status.NOT_FOUND, "Chat not found");

    const isParticipant = chat.participants.some((p: mongoose.Types.ObjectId) => p.toString() === userId);
    if (!isParticipant) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    // Pagination (reverse for latest first)
    const start = (page - 1) * limit;
    const end = start + limit;

    const total = chat.messages.length;
    const messages = chat.messages.slice().reverse().slice(start, end);

    return res.status(200).json({ success: true, meta: { page, limit, total }, data: messages });
});

export const getChatMessagesAdmin = catchAsync(async (req: Request, res: Response) => {
    const { chatId } = req.params;
    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);

    const chat = await Chat.findById(chatId).populate("participants", "name email role").lean();
    if (!chat) return sendResponse(res, status.NOT_FOUND, "Chat not found");

    const sortedMessages = [...chat.messages].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const startIndex = (page - 1) * limit;
    const paginatedMessages = sortedMessages.slice(startIndex, startIndex + limit);

    const totalMessages = chat.messages.length;
    const totalPages = Math.ceil(totalMessages / limit);

    const messages = paginatedMessages.map(msg => ({
        _id: msg._id,
        sender: msg.sender,
        content: msg.content,
        type: msg.type,
        timestamp: msg.timestamp,
        read: msg.read,
        image: msg.image
    }));

    return sendResponse(res, status.OK, "Chat messages fetched successfully", { total: totalMessages, page, limit, totalPages }, { chatId: chat._id, participants: chat.participants, messages });
});

export const deleteMessageAdmin = catchAsync(async (req: Request, res: Response) => {
    const { chatId, messageId } = req.params;

    const chat = await Chat.findById(chatId);
    if (!chat) return sendResponse(res, status.NOT_FOUND, "Chat not found");

    const messageIndex = chat.messages.findIndex((m) => m._id?.toString() === messageId);
    if (messageIndex === -1) return sendResponse(res, status.NOT_FOUND, "Message not found");

    const message = chat.messages[messageIndex];

    // If message has an image, delete it from Cloudinary
    if (message.image?.publicId) await deleteImage(message.image.publicId);

    // Message delete from chat
    chat.messages.splice(messageIndex, 1);

    // lastMessage and lastUpdated update
    chat.lastMessage = chat.messages.length ? chat.messages[chat.messages.length - 1].content : "";
    chat.lastUpdated = new Date();

    await chat.save();

    const io = req.app.get("io");
    io?.to(chatId).emit("messageDeleted", { messageId });

    return sendResponse(res, status.OK, "Message deleted successfully", { messageId });
});