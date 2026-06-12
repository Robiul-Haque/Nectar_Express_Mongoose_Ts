import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import Chat from "./chat.model";
import status from "http-status";
import sendResponse from "../../utils/sendResponse";

export const createChat = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { receiverId } = req.body;

    if (userId === receiverId) return sendResponse(res, status.BAD_REQUEST, "Cannot chat yourself");

    let chat = await Chat.findOne({ participants: { $all: [userId, receiverId] }, });
    if (!chat) chat = await Chat.create({ participants: [userId, receiverId] });

    return sendResponse(res, status.OK, "Chat ready", null, chat);
});

export const getMyChats = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { search } = req.query;

    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    // Build filter
    const filter: any = { participants: userId };
    
    // Add search filter for lastMessage if search term exists
    if (search && typeof search === "string" && search.trim()) {
        filter.lastMessage = { $regex: search, $options: "i" };
    }

    const [total, chats] = await Promise.all([
        Chat.countDocuments(filter),
        Chat.find(filter)
            .select("participants lastMessage lastUpdated")
            .sort({ lastUpdated: -1 })
            .skip(skip)
            .limit(limit)
            .populate({ path: "participants", select: "name email role avatar", options: { lean: true } })
            .lean()
    ]);

    const formattedChats = chats.map(chat => ({
        ...chat,
        participants: chat.participants.filter((p: any) => p._id.toString() !== userId).map((p: any) => ({
            ...p,
            avatar: p.avatar?.url || null
        }))
    }));

    const totalPages = Math.ceil(total / limit);

    return sendResponse(res, status.OK, "All chat fetch successfully", { total, page, limit, totalPages }, formattedChats);
});