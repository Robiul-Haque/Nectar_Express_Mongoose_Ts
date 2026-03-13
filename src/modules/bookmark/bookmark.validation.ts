import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createBookmarkSchema = z.object({
    body: z.object({ productId: objectIdSchema }).strict()
});

export const deleteBookmarkSchema = z.object({
    params: z.object({ id: objectIdSchema })
});

export const getBookmarksSchema = z.object({
    query: z.object({
        page: z.string().optional().transform((v) => Number(v) || 1),
        limit: z.string().optional().transform((v) => Number(v) || 10)
    })
});