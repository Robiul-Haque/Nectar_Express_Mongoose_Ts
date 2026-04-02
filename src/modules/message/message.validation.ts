import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const sendMessageSchema = z.object({
    body: z
        .object({
            chatId: objectIdSchema,
            content: z.string().trim().max(2000, "Message too long").optional(),
            type: z.enum(["text", "image"]).default("text")
        })
        .refine(
            (data) => {
                if (data.type === "text") return !!data.content && data.content.trim() !== "";
                return true;
            },
            {
                message: "Text message must have content",
                path: ["content"]
            }
        )
});

export const getMessagesSchema = z.object({
    params: z.object({
        chatId: objectIdSchema
    }),
    query: z.object({
        page: z.string().optional(),
        limit: z.string().optional()
    })
});

export const deleteMessageSchema = z.object({
    params: z.object({
        messageId: objectIdSchema
    })
});

export const markAsReadSchema = z.object({
    params: z.object({
        chatId: objectIdSchema,
    })
});