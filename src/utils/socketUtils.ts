import { Server, Socket } from "socket.io";
import jwt, { JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { env } from "../config/env";
import Chat from "../modules/chat/chat.model";
import Message from "../modules/message/message.model";
import { registerTrackingHandlers } from "../modules/tracking/tracking.socket";

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
        console.log(`✅ Socket Connected: ${socket.id} | User: ${userId}`);
        if (userId) socket.join(userId);

        socket.on("joinRoom", ({ chatId }: { chatId: string }) => {
            if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
            console.log(`🔵 Join Room: ${chatId} | Socket: ${socket.id}`);
            socket.join(chatId);
        });

        socket.on("sendMessage", async ({ chatId, content, type = "text" }: { chatId: string; content: string; type?: "text" | "image"; }) => {
            try {
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
                console.error("❌ sendMessage error:", error);
                socket.emit("error", "Failed to send message");
            }
        });

        socket.on("markAsRead", async (chatId: string) => {
            try {
                if (!userId || !mongoose.Types.ObjectId.isValid(chatId)) return;
                
                await Message.updateMany(
                    { chatId, readBy: { $ne: userId } }, 
                    { $addToSet: { readBy: userId } }
                );
                
                io.to(chatId).emit("messagesRead", { chatId, userId });
            } catch (error) {
                console.error("❌ markAsRead error:", error);
            }
        });

        socket.on("payment-listen", () => {
            if (userId) socket.join(userId);
        });

        // Register new tracking real-time handlers
        registerTrackingHandlers(io, socket);

        socket.on("disconnect", () => console.log(`🔴 Disconnected: ${socket.id} | User: ${userId}`));
    });
};