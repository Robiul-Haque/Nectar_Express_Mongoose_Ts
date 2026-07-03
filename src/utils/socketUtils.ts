import { Server, Socket } from "socket.io";
import jwt, { JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { env } from "../config/env";
import logger from "./logger";
import Chat from "../modules/chat/chat.model";
import Message from "../modules/message/message.model";
import { registerTrackingHandlers } from "../modules/tracking/tracking.socket";

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
    "sendMessage": { maxRequests: 30, windowMs: 60000 },       // 30 msg/min
    "driver:update-location": { maxRequests: 60, windowMs: 60000 }, // 60 updates/min
    "joinOrderTrack": { maxRequests: 20, windowMs: 60000 },    // 20 joins/min
    "markAsRead": { maxRequests: 60, windowMs: 60000 },        // 60 reads/min
    "joinRoom": { maxRequests: 30, windowMs: 60000 },          // 30 joins/min
};

function checkSocketRateLimit(socketId: string, event: string): boolean {
    const config = SOCKET_RATE_LIMITS[event];
    if (!config) return true; // no limit for this event

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
        return false; // rate limited
    }

    return true;
}

// Cleanup rate limit data when socket disconnects
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
}

export const initializeSocket = (io: Server) => {
    io.use((socket: AuthenticatedSocket, next) => {
        try {
            const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.split(" ")[1];
            if (!token) return next(new Error("Authentication token required"));

            const payload = jwt.verify(token, env.JWT_ACCESS_TOKEN) as SocketPayload;
            socket.user = payload;
            next();
        } catch (error) {
            next(new Error("Invalid or expired token"));
        }
    });

    io.on("connection", (socket: AuthenticatedSocket) => {
        const userId = socket.user?.sub;
        logger.info(`✅ Socket Connected: ${socket.id} | User: ${userId}`);
        if (userId) socket.join(userId);

        socket.on("joinRoom", ({ chatId }: { chatId: string }) => {
            if (!checkSocketRateLimit(socket.id, "joinRoom")) {
                return socket.emit("error", "Rate limit exceeded. Please slow down.");
            }
            if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
            logger.info(`🔵 Join Room: ${chatId} | Socket: ${socket.id}`);
            socket.join(chatId);
        });

        socket.on("sendMessage", async ({ chatId, content, type = "text" }: { chatId: string; content: string; type?: "text" | "image"; }) => {
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
                if (!isParticipant) return socket.emit("error", "Unauthorized");

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

                // Transform avatar to only URL
                const transformedMessage = {
                    ...populatedMessage.toObject(),
                    sender: {
                        ...populatedMessage.sender,
                        avatar: (populatedMessage.sender as any).avatar?.url || null
                    }
                };

                io.to(chatId).emit("newMessage", transformedMessage);
            } catch (error) {
                logger.error(`❌ sendMessage error: ${error instanceof Error ? error.message : String(error)}`);
                socket.emit("error", "Failed to send message");
            }
        });

        socket.on("markAsRead", async (chatId: string) => {
            try {
                if (!checkSocketRateLimit(socket.id, "markAsRead")) {
                    return socket.emit("error", "Rate limit exceeded. Please slow down.");
                }
                if (!userId || !mongoose.Types.ObjectId.isValid(chatId)) return;
                
                await Message.updateMany(
                    { chatId, readBy: { $ne: userId } }, 
                    { $addToSet: { readBy: userId } }
                );
                
                io.to(chatId).emit("messagesRead", { chatId, userId });
            } catch (error) {
                logger.error(`❌ markAsRead error: ${error instanceof Error ? error.message : String(error)}`);
            }
        });

        socket.on("payment-listen", () => {
            if (userId) socket.join(userId);
        });

        // Register new tracking real-time handlers
        registerTrackingHandlers(io, socket);

        socket.on("disconnect", () => {
            cleanupSocketRateLimit(socket.id);
            logger.info(`🔴 Disconnected: ${socket.id} | User: ${userId}`);
        });
    });
};