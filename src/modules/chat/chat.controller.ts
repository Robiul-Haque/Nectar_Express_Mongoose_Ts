import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import Chat from "./chat.model";
import Message from "../message/message.model";
import User from "../user/user.model";
import Order from "../order/order.model";
import status from "http-status";
import sendResponse from "../../utils/sendResponse";
import { isUserOnline } from "../../utils/socketUtils";

export const createChat = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;
    let { receiverId } = req.body || {};

    // If no receiverId provided (e.g. Customer or Driver opening support chat)
    if (!receiverId) {
        if (userRole === "admin") {
            return sendResponse(res, status.BAD_REQUEST, "Admin must specify a receiverId to start a chat");
        }
        // Find an admin user
        const adminUser = await User.findOne({ role: "admin" }).select("_id").lean();
        if (!adminUser) {
            return sendResponse(res, status.INTERNAL_SERVER_ERROR, "No support admin available at the moment");
        }
        receiverId = adminUser._id.toString();
    }

    if (userId === receiverId) {
        return sendResponse(res, status.BAD_REQUEST, "Cannot chat yourself");
    }

    const determinedChatType = userRole === "driver" ? "driver_support" : (userRole === "admin" ? "direct" : "customer_support");

    let chat = await Chat.findOne({ participants: { $all: [userId, receiverId] } });
    if (!chat) {
        chat = await Chat.create({
            participants: [userId, receiverId],
            chatType: determinedChatType,
            status: "open",
            lastUpdated: new Date()
        });
    }

    return sendResponse(res, status.OK, "Chat ready", null, chat);
});

export const getMyChats = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;
    const { search, chatType, status: chatStatus } = req.query;

    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    // Build filter
    const filter: any = {};

    if (userRole === "admin") {
        // Admin can view all chats or filter by chatType/status
        if (chatType) {
            if (chatType === "customer_support") {
                filter.$or = [{ chatType: "customer_support" }, { chatType: { $exists: false } }, { chatType: null }];
            } else {
                filter.chatType = chatType;
            }
        }
        if (chatStatus) filter.status = chatStatus;
    } else {
        // Normal user/driver sees their own chats
        filter.participants = userId;
        if (chatStatus) filter.status = chatStatus;
    }

    if (search && typeof search === "string" && search.trim()) {
        filter.lastMessage = { $regex: search, $options: "i" };
    }

    const [total, chats] = await Promise.all([
        Chat.countDocuments(filter),
        Chat.find(filter)
            .select("participants lastMessage lastUpdated status chatType createdAt")
            .sort({ lastUpdated: -1 })
            .skip(skip)
            .limit(limit)
            .populate({ path: "participants", select: "name email role avatar isActive", options: { lean: true } })
            .lean()
    ]);

    // Calculate unread messages count per chat
    const chatIds = chats.map(c => c._id);
    const unreadCountsRaw = await Message.aggregate([
        {
            $match: {
                chatId: { $in: chatIds },
                readBy: { $ne: userId }
            }
        },
        {
            $group: {
                _id: "$chatId",
                count: { $sum: 1 }
            }
        }
    ]);

    const unreadMap = new Map<string, number>();
    unreadCountsRaw.forEach(item => unreadMap.set(item._id.toString(), item.count));

    const formattedChats = chats.map(chat => {
        const otherParticipants = (chat.participants || [])
            .filter((p: any) => p && p._id && p._id.toString() !== userId)
            .map((p: any) => ({
                ...p,
                avatar: p.avatar?.url || null,
                isOnline: p._id ? isUserOnline(p._id.toString()) : false
            }));

        return {
            ...chat,
            participants: otherParticipants.length > 0 ? otherParticipants : (chat.participants || []).map((p: any) => ({
                ...p,
                avatar: p?.avatar?.url || null,
                isOnline: p?._id ? isUserOnline(p._id.toString()) : false
            })),
            unreadCount: unreadMap.get(chat._id.toString()) || 0
        };
    });

    const totalPages = Math.ceil(total / limit);

    return sendResponse(res, status.OK, "All chat fetched successfully", { total, page, limit, totalPages }, formattedChats);
});

export const getChatById = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;
    const { chatId } = req.params;

    const chat = await Chat.findById(chatId)
        .populate({ path: "participants", select: "name email role avatar location notificationEnabled createdAt", options: { lean: true } })
        .lean();

    if (!chat) {
        return sendResponse(res, status.NOT_FOUND, "Chat not found");
    }

    const isParticipant = chat.participants.some((p: any) => p._id.toString() === userId);
    if (userRole !== "admin" && !isParticipant) {
        return sendResponse(res, status.FORBIDDEN, "Unauthorized");
    }

    // Get unread count
    const unreadCount = await Message.countDocuments({ chatId, readBy: { $ne: userId } });

    // Find non-admin participant for context info
    const customerParticipant = chat.participants.find((p: any) => p.role !== "admin") || chat.participants[0];

    let relatedOrder = null;
    if (customerParticipant) {
        relatedOrder = await Order.findOne({ user: customerParticipant._id })
            .select("orderId orderStatus totalAmount paymentStatus createdAt")
            .sort({ createdAt: -1 })
            .lean();
    }

    const formattedParticipants = chat.participants.map((p: any) => ({
        ...p,
        avatar: p.avatar?.url || null,
        isOnline: p._id ? isUserOnline(p._id.toString()) : false
    }));

    return sendResponse(res, status.OK, "Chat details fetched", null, {
        ...chat,
        participants: formattedParticipants,
        unreadCount,
        relatedOrder
    });
});

export const updateChatStatus = catchAsync(async (req: Request, res: Response) => {
    const { chatId } = req.params;
    const { status: newStatus } = req.body;

    const chat = await Chat.findByIdAndUpdate(
        chatId,
        { status: newStatus, lastUpdated: new Date() },
        { new: true }
    ).populate({ path: "participants", select: "name email role avatar" }).lean();

    if (!chat) {
        return sendResponse(res, status.NOT_FOUND, "Chat not found");
    }

    const io = req.app.get("io");
    if (io) {
        io.emit("conversation:status", { chatId, status: newStatus });
        io.emit("chatStatusUpdated", { chatId, status: newStatus });
        io.to(chatId).emit("conversation:status", { chatId, status: newStatus });
        io.to(chatId).emit("chatStatusUpdated", { chatId, status: newStatus });
    }

    return sendResponse(res, status.OK, `Chat status updated to ${newStatus}`, null, chat);
});