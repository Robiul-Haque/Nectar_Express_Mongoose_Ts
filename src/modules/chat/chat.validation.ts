import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const optionalObjectIdSchema = z
    .string()
    .optional()
    .nullable()
    .transform((val) => (val === "" || val === null ? undefined : val))
    .refine((val) => !val || mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createChatSchema = z.object({
    body: z.object({
        receiverId: optionalObjectIdSchema
    }).optional().default({})
});

export const chatIdParamSchema = z.object({
    params: z.object({
        chatId: objectIdSchema
    })
});

export const getChatsQuerySchema = z.object({
    query: z.object({
        page: z.string().optional().refine((val) => !val || !isNaN(Number(val)), { message: "Page must be a number" }),
        limit: z.string().optional().refine((val) => !val || !isNaN(Number(val)), { message: "Limit must be a number" }),
        chatType: z.enum(["customer_support", "driver_support", "direct"]).optional(),
        status: z.enum(["open", "resolved"]).optional(),
        search: z.string().optional()
    }).optional().default({})
});

export const updateChatStatusSchema = z.object({
    params: z.object({
        chatId: objectIdSchema
    }),
    body: z.object({
        status: z.enum(["open", "resolved"])
    })
});