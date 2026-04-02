import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import status from "http-status";
import sendResponse from "../../utils/sendResponse";
import Chat from "../chat/chat.model";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import Message from "./message.model";

export const sendMessage = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId, content, type = "text" } = req.body;
    const fileBuffer = req.file?.buffer;

    const chat = await Chat.findById(chatId);
    if (!chat) return sendResponse(res, 404, "Chat not found");
    if (!chat.participants.some(p => p.toString() === userId)) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    let imageData = null;

    if (type === "image") {
        if (!fileBuffer) throw new Error("Image file required");

        const upload = await uploadImageStream(fileBuffer, { folder: "chat_messages" });
        imageData = { url: upload.secure_url, publicId: upload.public_id };
    }

    if (type === "text" && !content?.trim()) return sendResponse(res, status.BAD_REQUEST, "Text content cannot be empty");

    const message = await Message.create({
        chatId,
        sender: userId,
        content: type === "text" ? content.trim() : "📷 Image",
        type,
        image: imageData,
        readBy: [userId]
    });

    await Chat.findByIdAndUpdate(chatId, { lastMessage: message.content, lastUpdated: new Date() });

    const io = req.app.get("io");
    io?.to(chatId).emit("newMessage", message);

    return sendResponse(res, status.OK, "Message sent", null, message);
});


export const getChatMessages = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId } = req.params;

    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 20, 50);

    const chat = await Chat.findById(chatId);
    if (!chat) return sendResponse(res, 404, "Chat not found");

    if (!chat.participants.includes(userId as any)) return sendResponse(res, status.FORBIDDEN, "Unauthorized");

    const messages = await Message.find({ chatId }).populate("sender", "name email role").sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);
    const total = await Message.countDocuments({ chatId });

    return sendResponse(res, status.OK, "Messages fetched", { pagination: { page, limit, total }, data: messages });
});

export const deleteMessageAdmin = catchAsync(async (req: Request, res: Response) => {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);
    if (!message) return sendResponse(res, status.NOT_FOUND, "Message not found");
    if (message.image?.publicId) await deleteImage(message.image.publicId);
    await message.deleteOne();

    const io = req.app.get("io");
    io?.to(message.chatId.toString()).emit("messageDeleted", { messageId });

    return sendResponse(res, status.OK, "Message deleted", { messageId });
});

export const markAsRead = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { chatId } = req.params;

    await Message.updateMany({ chatId, readBy: { $ne: userId } }, { $addToSet: { readBy: userId } });

    return sendResponse(res, status.OK, "Marked as read");
});