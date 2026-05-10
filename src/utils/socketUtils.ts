import { Server, Socket } from "socket.io";
import jwt, { JwtPayload } from "jsonwebtoken";
import mongoose from "mongoose";
import { env } from "../config/env";
import Chat from "../modules/chat/chat.model";

interface SocketPayload extends JwtPayload {
    sub: string;
    role: "user" | "admin";
    provider?: string;
    v?: number;
}

// ✅ Proper extended socket
interface AuthenticatedSocket extends Socket {
    user?: SocketPayload;
}

export const initializeSocket = (io: Server) => {

    // 🔐 AUTH MIDDLEWARE (ENABLE THIS)
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

        // JOIN ROOM
        socket.on("joinRoom", ({ chatId }: { chatId: string }) => {
            if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
            console.log(`🔵 Join Room: ${chatId} | Socket: ${socket.id}`);

            socket.join(chatId);
        });

        // SEND MESSAGE
        socket.on("sendMessage", async ({ chatId, content, type = "text" }: { chatId: string; content: string; type?: "text" | "image"; }) => {
            try {
                if (!userId) return socket.emit("error", "Unauthorized");

                if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
                if (!content?.trim()) return socket.emit("error", "Message content required");

                const chat = await Chat.findById(chatId).select("participants").exec();
                if (!chat) return socket.emit("error", "Chat not found");

                const isParticipant = chat.participants.some((p: any) => p.toString() === userId);
                if (!isParticipant) return socket.emit("error", "Unauthorized");

                const message = {
                    sender: new mongoose.Types.ObjectId(userId),
                    content: content.trim(),
                    type,
                    timestamp: new Date(),
                    read: false,
                };

                await Chat.updateOne({ _id: chatId }, { $push: { messages: message }, $set: { lastUpdated: new Date() }, });

                io.to(chatId).emit("newMessage", { ...message, sender: userId });

            } catch (error) {
                console.error("❌ sendMessage error:", error);
                socket.emit("error", "Failed to send message");
            }
        }
        );

        // MARK AS READ
        socket.on("markAsRead", async (chatId: string) => {
            try {
                if (!mongoose.Types.ObjectId.isValid(chatId)) return;

                await Chat.updateOne({ _id: chatId }, { $set: { "messages.$[].read": true } });
                io.to(chatId).emit("messagesRead", { chatId });
            } catch (error) {
                console.error("❌ markAsRead error:", error);
            }
        });

        // DISCONNECT
        socket.on("disconnect", () => {
            console.log(`🔴 Disconnected: ${socket.id} | User: ${userId}`);
        });
    });
};