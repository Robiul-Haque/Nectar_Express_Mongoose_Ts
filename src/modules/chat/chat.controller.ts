import { Request, Response } from "express";
import Chat from "./chat.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

export const createOrGetChat = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { receiverId } = req.body;

    if (userId === receiverId) return sendResponse(res, status.BAD_REQUEST, "Cannot chat yourself");

    let chat = await Chat.findOne({ participants: { $all: [userId, receiverId] }, });
    if (!chat) chat = await Chat.create({ participants: [userId, receiverId] });

    return sendResponse(res, status.OK, "Chat ready", null, chat);
});

export const getMyChats = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;

    // page & limit query param
    const page = Math.max(Number(req.query.page) || 1, 1);
    const limit = Math.min(Number(req.query.limit) || 20, 100); // max 100

    const skip = (page - 1) * limit;

    // Chats query
    const [total, chats] = await Promise.all([
        Chat.countDocuments({ participants: userId }),
        Chat.find({ participants: userId })
            .populate("participants", "name email role")
            .sort({ lastUpdated: -1 })
            .skip(skip)
            .limit(limit)
    ]);

    const totalPages = Math.ceil(total / limit);

    return sendResponse(res, status.OK, "Chats fetched", {
        total,
        page,
        limit,
        totalPages
    }, chats);
});