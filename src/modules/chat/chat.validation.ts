import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createChatSchema = z.object({
    body: z.object({
        receiverId: objectIdSchema
    })
});

export const chatIdParamSchema = z.object({
    chatId: objectIdSchema
});

export const getChatsQuerySchema = z.object({
    query: z.object({
        page: z.string().optional().refine((val) => !val || !isNaN(Number(val)), { message: "Page must be a number" }),
        limit: z.string().optional().refine((val) => !val || !isNaN(Number(val)), { message: "Limit must be a number" }),
    })
});