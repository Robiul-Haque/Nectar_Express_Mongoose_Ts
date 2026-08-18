import { Server, Socket } from "socket.io";
import jwt, { JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { env } from "../config/env";
import logger from "./logger";
import Chat from "../modules/chat/chat.model";
import Message from "../modules/message/message.model";
import { registerTrackingHandlers } from "../modules/tracking/tracking.socket";

// In-memory global online user connection tracker (userId -> Set of active socket IDs)
const onlineUsersMap = new Map<string, Set<string>>();

// In-memory active room participants tracker
// chatId -> Set of active socket IDs
const roomActiveAdminsMap = new Map<string, Set<string>>();
const roomActiveUsersMap = new Map<string, Set<string>>();

export const isUserOnline = (userId: string): boolean => {
    if (!userId) return false;
    const socketSet = onlineUsersMap.get(userId.toString());
    return Boolean(socketSet && socketSet.size > 0);
};

export const isRoomAdminActive = (chatId: string): boolean => {
    if (!chatId) return false;
    const adminSet = roomActiveAdminsMap.get(chatId.toString());
    return Boolean(adminSet && adminSet.size > 0);
};

export const isRoomUserActive = (chatId: string): boolean => {
    if (!chatId) return false;
    const userSet = roomActiveUsersMap.get(chatId.toString());
    return Boolean(userSet && userSet.size > 0);
};

// In-memory socket rate limiter (per socket, per event type)
const socketRateLimits = new Map<string, Map<string, { count: number; resetAt: number }>>();

// Periodic cleanup of stale rate limit entries (every 5 minutes)
setInterval(() => {
    const now = Date.now();
    for (const [socketId, limits] of socketRateLimits.entries()) {
        let allExpired = true;
        for (const limit of limits.values()) {
            if (now <= limit.resetAt) {
                allExpired = false;
                break;
            }
        }
        if (allExpired) {
            socketRateLimits.delete(socketId);
        }
    }
}, 5 * 60 * 1000).unref();

const SOCKET_RATE_LIMITS: Record<string, { maxRequests: number; windowMs: number }> = {
    "sendMessage": { maxRequests: 30, windowMs: 60000 },
    "driver:update-location": { maxRequests: 60, windowMs: 60000 },
    "joinOrderTrack": { maxRequests: 20, windowMs: 60000 },
    "markAsRead": { maxRequests: 60, windowMs: 60000 },
    "joinRoom": { maxRequests: 40, windowMs: 60000 },
};

function checkSocketRateLimit(socketId: string, event: string): boolean {
    const config = SOCKET_RATE_LIMITS[event];
    if (!config) return true;

    const now = Date.now();
    let socketLimits = socketRateLimits.get(socketId);

    if (!socketLimits) {
        socketLimits = new Map();
        socketRateLimits.set(socketId, socketLimits);
    }

    let eventLimit = socketLimits.get(event);
    if (!eventLimit || now > eventLimit.resetAt) {
        eventLimit = { count: 0, resetAt: now + config.windowMs };
        socketLimits.set(event, eventLimit);
    }

    eventLimit.count++;

    if (eventLimit.count > config.maxRequests) {
        return false;
    }

    return true;
}

function cleanupSocketRateLimit(socketId: string) {
    socketRateLimits.delete(socketId);
}

interface SocketPayload extends JwtPayload {
    sub: string;
    role: "user" | "admin" | "driver";
    provider?: string;
    v?: number;
}

interface AuthenticatedSocket extends Socket {
    user?: SocketPayload;
    activeRooms?: Set<string>;
}

export const initializeSocket = (io: Server) => {
    io.use((socket: AuthenticatedSocket, next) => {
        try {
            const authToken = socket.handshake.auth?.token;
            const headerAuth = socket.handshake.headers?.authorization;
            let token: string | undefined;

            if (authToken && typeof authToken === 'string') {
                token = authToken.startsWith('Bearer ')
                    ? authToken.slice(7).trim()
                    : authToken.trim();
            } else if (headerAuth) {
                token = headerAuth.startsWith('Bearer ')
                    ? headerAuth.slice(7).trim()
                    : headerAuth.trim();
            }

            if (!token) return next(new Error("Authentication token required"));

            const payload = jwt.verify(token, env.JWT_ACCESS_TOKEN) as SocketPayload;
            socket.user = payload;
            socket.activeRooms = new Set<string>();
            next();
        } catch (error) {
            logger.warn(`[Socket] Auth error: ${error instanceof Error ? error.message : String(error)}`);
            next(new Error("Invalid or expired token"));
        }
    });

    io.on("connection", (socket: AuthenticatedSocket) => {
        const userId = socket.user?.sub;
        const userIdStr = userId ? userId.toString() : null;
        const userRole = socket.user?.role;
        logger.info(`✅ Socket Connected: ${socket.id} | User: ${userIdStr} | Role: ${userRole}`);

        if (userIdStr) {
            socket.join(userIdStr);
            if (userRole === "admin") {
                socket.join("admins");
            }

            let userSockets = onlineUsersMap.get(userIdStr);
            if (!userSockets) {
                userSockets = new Set();
                onlineUsersMap.set(userIdStr, userSockets);
            }
            userSockets.add(socket.id);

            io.emit("userStatusChanged", { userId: userIdStr, isOnline: true });
            io.emit("user:online", { userId: userIdStr });
        }

        socket.on("getOnlineUsers", () => {
            socket.emit("onlineUsersList", { onlineUserIds: Array.from(onlineUsersMap.keys()) });
        });
        socket.on("users:online:get", () => {
            socket.emit("onlineUsersList", { onlineUserIds: Array.from(onlineUsersMap.keys()) });
        });

        socket.on("user:active", () => {
            if (userIdStr) {
                let userSockets = onlineUsersMap.get(userIdStr);
                if (!userSockets) {
                    userSockets = new Set();
                    onlineUsersMap.set(userIdStr, userSockets);
                }
                userSockets.add(socket.id);
                io.emit("userStatusChanged", { userId: userIdStr, isOnline: true });
                io.emit("user:online", { userId: userIdStr });
            }
        });

        const handleJoinRoom = async (data: any) => {
            const chatId = typeof data === "string" ? data : data?.chatId;
            if (!checkSocketRateLimit(socket.id, "joinRoom")) {
                return socket.emit("error", "Rate limit exceeded. Please slow down.");
            }
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");

            if (userRole !== "admin") {
                const chat = await Chat.findById(chatId).select("participants").lean();
                if (!chat || !chat.participants.some((p: any) => p.toString() === userIdStr)) {
                    return socket.emit("error", "Unauthorized room access");
                }
            }

            const chatIdStr = chatId.toString();
            socket.join(chatIdStr);
            socket.activeRooms?.add(chatIdStr);

            if (userRole === "admin") {
                let adminSockets = roomActiveAdminsMap.get(chatIdStr);
                if (!adminSockets) {
                    adminSockets = new Set();
                    roomActiveAdminsMap.set(chatIdStr, adminSockets);
                }
                adminSockets.add(socket.id);

                logger.info(`🔵 Admin Joined Room: ${chatIdStr} | Socket: ${socket.id}`);
                io.to(chatIdStr).emit("admin:status", { chatId: chatIdStr, isOnline: true });
                io.to(chatIdStr).emit("room:presence", {
                    chatId: chatIdStr,
                    isAdminOnline: true,
                    isUserOnline: isRoomUserActive(chatIdStr),
                });
            } else {
                let userSockets = roomActiveUsersMap.get(chatIdStr);
                if (!userSockets) {
                    userSockets = new Set();
                    roomActiveUsersMap.set(chatIdStr, userSockets);
                }
                userSockets.add(socket.id);

                logger.info(`🔵 Customer Joined Room: ${chatIdStr} | Socket: ${socket.id}`);
                const hasAdmin = isRoomAdminActive(chatIdStr);
                socket.emit("admin:status", { chatId: chatIdStr, isOnline: hasAdmin });
                socket.emit("room:presence", {
                    chatId: chatIdStr,
                    isAdminOnline: hasAdmin,
                    isUserOnline: true,
                });
                io.to(chatIdStr).emit("userStatusChanged", { chatId: chatIdStr, userId: userIdStr, isOnline: true });
            }
        };

        const handleLeaveRoom = (data: any) => {
            const chatId = typeof data === "string" ? data : data?.chatId;
            if (!chatId || !mongoose.Types.ObjectId.isValid(chatId)) return;
            const chatIdStr = chatId.toString();

            logger.info(`⚪ Leave Room: ${chatIdStr} | Socket: ${socket.id}`);
            socket.leave(chatIdStr);
            socket.activeRooms?.delete(chatIdStr);

            if (userRole === "admin") {
                const adminSockets = roomActiveAdminsMap.get(chatIdStr);
                if (adminSockets) {
                    adminSockets.delete(socket.id);
                    if (adminSockets.size === 0) {
                        roomActiveAdminsMap.delete(chatIdStr);
                        io.to(chatIdStr).emit("admin:status", { chatId: chatIdStr, isOnline: false });
                        io.to(chatIdStr).emit("room:presence", {
                            chatId: chatIdStr,
                            isAdminOnline: false,
                            isUserOnline: isRoomUserActive(chatIdStr),
                        });
                    }
                }
            } else {
                const userSockets = roomActiveUsersMap.get(chatIdStr);
                if (userSockets) {
                    userSockets.delete(socket.id);
                    if (userSockets.size === 0) {
                        roomActiveUsersMap.delete(chatIdStr);
                        io.to(chatIdStr).emit("userStatusChanged", { chatId: chatIdStr, userId: userIdStr, isOnline: false });
                    }
                }
            }
        };

        const handleSendMessage = async ({ chatId, content, type = "text" }: { chatId: string; content: string; type?: "text" | "image"; }) => {
            try {
                if (!checkSocketRateLimit(socket.id, "sendMessage")) {
                    return socket.emit("error", "Rate limit exceeded. Please slow down.");
                }
                if (!userId) return socket.emit("error", "Unauthorized");
                if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
                if (type === "text" && !content?.trim()) return socket.emit("error", "Message content required");

                const chat = await Chat.findById(chatId).select("participants").exec();
                if (!chat) return socket.emit("error", "Chat not found");

                const isParticipant = chat.participants.some((p: any) => p.toString() === userId);
                if (userRole !== "admin" && !isParticipant) return socket.emit("error", "Unauthorized");

                // Create message in DB
                const message = await Message.create({
                    chatId,
                    sender: userId,
                    content: type === "text" ? content.trim() : "📷 Image",
                    type,
                    readBy: [userId]
                });

                // Update chat
                await Chat.findByIdAndUpdate(chatId, { 
                    lastMessage: message.content, 
                    lastUpdated: new Date() 
                });

                // Populate sender for socket event
                const populatedMessage = await message.populate({
                    path: "sender",
                    select: "name email role avatar"
                });

                // Transform avatar to URL string while preserving all sender fields
                const msgObj = populatedMessage.toObject();
                const rawSender = msgObj.sender as any;
                const transformedMessage = {
                    ...msgObj,
                    sender: rawSender ? {
                        ...rawSender,
                        avatar: rawSender?.avatar?.url || (typeof rawSender?.avatar === "string" ? rawSender.avatar : null)
                    } : null
                };

                const chatIdStr = chatId.toString();
                // Emit to chat room (both event names for backward compatibility)
                io.to(chatIdStr).emit("newMessage", transformedMessage);
                io.to(chatIdStr).emit("message:new", transformedMessage);

                // Emit to each participant's personal room and admins room.
                // Only emit "newMessage" (not also "message:new") to avoid
                // amplification — admins/participants already receive the event
                // from the chat room they joined. The personal-room emit is a
                // fallback for clients that haven't joined the chat room yet
                // (e.g., chat list showing unread badge).
                chat.participants.forEach((p: any) => {
                    io.to(p.toString()).emit("newMessage", transformedMessage);
                });
                io.to("admins").emit("newMessage", transformedMessage);
            } catch (error) {
                logger.error(`❌ sendMessage error: ${error instanceof Error ? error.message : String(error)}`);
                socket.emit("error", "Failed to send message");
            }
        };

        const handleMarkAsRead = async (chatIdParam: string | { chatId: string }) => {
            try {
                const chatId = typeof chatIdParam === "string" ? chatIdParam : chatIdParam?.chatId;
                if (!checkSocketRateLimit(socket.id, "markAsRead")) {
                    return socket.emit("error", "Rate limit exceeded. Please slow down.");
                }
                if (!userId || !chatId || !mongoose.Types.ObjectId.isValid(chatId)) return;
                
                await Message.updateMany(
                    { chatId, readBy: { $ne: userId } }, 
                    { $addToSet: { readBy: userId } }
                );
                
                const chatIdStr = chatId.toString();
                const userIdStr = userId.toString();
                // Emit to chat room (both event names for backward compat)
                io.to(chatIdStr).emit("messagesRead", { chatId: chatIdStr, userId: userIdStr });
                io.to(chatIdStr).emit("message:read", { chatId: chatIdStr, userId: userIdStr });

                // Participant personal rooms — single event name only
                const chat = await Chat.findById(chatId).select("participants").lean();
                if (chat && chat.participants) {
                    chat.participants.forEach((p: any) => {
                        io.to(p.toString()).emit("messagesRead", { chatId: chatIdStr, userId: userIdStr });
                    });
                }
            } catch (error) {
                logger.error(`❌ markAsRead error: ${error instanceof Error ? error.message : String(error)}`);
            }
        };

        socket.on("joinRoom", handleJoinRoom);
        socket.on("leaveRoom", handleLeaveRoom);
        socket.on("conversation:join", handleJoinRoom);
        socket.on("conversation:leave", handleLeaveRoom);
        socket.on("sendMessage", handleSendMessage);
        socket.on("message:send", handleSendMessage);
        socket.on("markAsRead", handleMarkAsRead);
        socket.on("message:read", handleMarkAsRead);

        const handleTypingStartEvent = (data: any) => {
            const chatId = typeof data === "string" ? data : data?.chatId;
            if (chatId && userIdStr) {
                socket.to(chatId.toString()).emit("typing:start", { chatId: chatId.toString(), userId: userIdStr });
            }
        };

        const handleTypingStopEvent = (data: any) => {
            const chatId = typeof data === "string" ? data : data?.chatId;
            if (chatId && userIdStr) {
                socket.to(chatId.toString()).emit("typing:stop", { chatId: chatId.toString(), userId: userIdStr });
            }
        };

        socket.on("typing:start", handleTypingStartEvent);
        socket.on("typing:stop", handleTypingStopEvent);

        socket.on("payment-listen", () => {
            if (userId) socket.join(userId);
        });

        // Register new tracking real-time handlers
        registerTrackingHandlers(io, socket);

        socket.on("disconnect", () => {
            cleanupSocketRateLimit(socket.id);

            // Clean up from active rooms
            if (socket.activeRooms && socket.activeRooms.size > 0) {
                for (const activeChatId of socket.activeRooms) {
                    if (userRole === "admin") {
                        const adminSockets = roomActiveAdminsMap.get(activeChatId);
                        if (adminSockets) {
                            adminSockets.delete(socket.id);
                            if (adminSockets.size === 0) {
                                roomActiveAdminsMap.delete(activeChatId);
                                io.to(activeChatId).emit("admin:status", { chatId: activeChatId, isOnline: false });
                                io.to(activeChatId).emit("room:presence", {
                                    chatId: activeChatId,
                                    isAdminOnline: false,
                                    isUserOnline: isRoomUserActive(activeChatId),
                                });
                            }
                        }
                    } else {
                        const userSockets = roomActiveUsersMap.get(activeChatId);
                        if (userSockets) {
                            userSockets.delete(socket.id);
                            if (userSockets.size === 0) {
                                roomActiveUsersMap.delete(activeChatId);
                                io.to(activeChatId).emit("userStatusChanged", { chatId: activeChatId, userId: userIdStr, isOnline: false });
                            }
                        }
                    }
                }
            }

            if (userIdStr) {
                const userSockets = onlineUsersMap.get(userIdStr);
                if (userSockets) {
                    userSockets.delete(socket.id);
                    if (userSockets.size === 0) {
                        onlineUsersMap.delete(userIdStr);
                        io.emit("userStatusChanged", { userId: userIdStr, isOnline: false });
                        io.emit("user:offline", { userId: userIdStr });
                    }
                }
            }
            logger.info(`🔴 Disconnected: ${socket.id} | User: ${userIdStr}`);
        });
    });
};
