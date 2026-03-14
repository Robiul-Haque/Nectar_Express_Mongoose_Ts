import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createBookmarkSchema = z.object({
    body: z.object({ productId: objectIdSchema }).strict()
});

export const getBookmarksSchema = z.object({
    query: z.object({
        page: z.string().optional().transform((v) => (v ? Number(v) : 1)).refine((v) => v > 0, { message: "Page must be greater than 0" }),
        limit: z.string().optional().transform((v) => (v ? Number(v) : 10)).refine((v) => v > 0 && v <= 100, { message: "Limit must be between 1 and 100" })
    }).strict()
});

export const deleteBookmarkSchema = z.object({
    params: z.object({ id: objectIdSchema })
});