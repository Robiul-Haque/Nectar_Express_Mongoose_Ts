import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createReviewSchema = z.object({
    body: z.object({
        productId: objectIdSchema,
        rating: z.coerce.number().min(1, "Rating must be at least 1").max(5, "Rating cannot exceed 5"),
        comment: z.string().max(1000).optional()
    })
});

export const updateReviewSchema = z.object({
    params: z.object({
        id: objectIdSchema
    }),
    body: z
        .object({
            rating: z.coerce.number().min(1, "Rating must be at least 1").max(5, "Rating cannot exceed 5").optional(),
            comment: z.string().trim().max(1000, "Comment cannot exceed 1000 characters").optional()
        })
        .refine((data) => Object.keys(data).length > 0, { message: "At least one field must be provided to update" })
});