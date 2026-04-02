import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine(val => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const sendMessageSchema = z.object({
    body: z.object({
        chatId: objectIdSchema,
        content: z.string().trim().max(2000).optional(),
        type: z.enum(["text", "image"]).default("text")
    }).refine(data => {
        if (data.type === "text" && (!data.content || data.content.trim() === "")) return false;
        return true;
    }, { message: "Text messages must have content" })
});

export const chatIdParamSchema = z.object({
    chatId: objectIdSchema
});

export const chatMessageIdParamSchema = z.object({
    chatId: objectIdSchema,
    messageId: objectIdSchema
});