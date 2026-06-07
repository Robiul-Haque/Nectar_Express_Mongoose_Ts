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

export const getProductReviewsSchema = z.object({
    query: z
        .object({
            productId: objectIdSchema,
            page: z.string().optional().transform((val) => (val ? Number(val) : 1)).refine((val) => !isNaN(val) && val > 0, { message: "Page must be a positive number" }),
            limit: z.string().optional().transform((val) => (val ? Number(val) : 10)).refine((val) => !isNaN(val) && val > 0 && val <= 100, { message: "Limit must be between 1 and 100" })
        })
        .strict()
});

export const updateReviewSchema = z.object({
    body: z.object({
        reviewId: objectIdSchema,
        rating: z.coerce.number().min(1, "Rating must be at least 1").max(5, "Rating cannot exceed 5").optional(),
        comment: z.string().trim().max(1000, "Comment cannot exceed 1000 characters").optional()
    }).refine((data) => Object.keys(data).length > 0, { message: "At least one field must be provided to update" })
});

export const deleteReviewSchema = z.object({
    params: z.object({ id: objectIdSchema }).strict()
});