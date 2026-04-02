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

// Extend socket type (clean & type-safe)
interface AuthenticatedSocket extends Socket { user?: SocketPayload }

export const initializeSocket = (io: Server) => {
    io.use((socket: AuthenticatedSocket, next) => {
        try {
            const token = socket.handshake.auth?.token;
            if (!token) return next(new Error("Authentication token required"));

            const payload = jwt.verify(token, env.JWT_ACCESS_TOKEN) as SocketPayload;
            socket.user = payload;
            next();
        } catch (error) {
            return next(new Error("Invalid or expired token"));
        }
    });

    io.on("connection", (socket: AuthenticatedSocket) => {
        const user = socket.user!;
        console.log(`✅ Socket Connected: ${socket.id} | User: ${user.sub}`);

        socket.on("joinRoom", (chatId: string) => {
            if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");

            socket.join(chatId);
        });

        socket.on("sendMessage", async ({ chatId, content, type = "text" }: { chatId: string; content: string; type?: "text" | "image" }) => {
            try {
                if (!mongoose.Types.ObjectId.isValid(chatId)) return socket.emit("error", "Invalid chatId");
                if (!content || content.trim().length === 0) return socket.emit("error", "Message content required");

                const chat = await Chat.findById(chatId).select("participants messages").exec();
                if (!chat) return socket.emit("error", "Chat not found");

                const isParticipant = chat.participants.some((p: mongoose.Types.ObjectId) => p.toString() === user.sub);
                if (!isParticipant) return socket.emit("error", "Unauthorized");

                const message = {
                    sender: new mongoose.Types.ObjectId(user.sub),
                    content: content.trim(),
                    type,
                    timestamp: new Date(),
                    read: false
                };

                // Atomic update (better than save())
                await Chat.updateOne({ _id: chatId }, { $push: { messages: message }, $set: { lastUpdated: new Date() } });

                //  Broadcast room with sender info (for client-side UI updates)
                io.to(chatId).emit("newMessage", { ...message, sender: user.sub });

            } catch (error) {
                console.error("❌ sendMessage error:", error);
                socket.emit("error", "Failed to send message");
            }
        }
        );

        // Mark messages as read
        socket.on("markAsRead", async (chatId: string) => {
            try {
                if (!mongoose.Types.ObjectId.isValid(chatId)) return;

                await Chat.updateOne({ _id: chatId, "messages.read": false }, { $set: { "messages.$[].read": true } });
                io.to(chatId).emit("messagesRead", { chatId });
            } catch (error) {
                console.error("❌ markAsRead error:", error);
            }
        });

        socket.on("disconnect", () => console.log(`🔴 Disconnected: ${socket.id} | User: ${user.sub}`));
    });
};