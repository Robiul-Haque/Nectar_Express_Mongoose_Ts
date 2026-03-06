import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createReviewSchema = z.object({
    body: z.object({
        product: objectIdSchema,
        rating: z.coerce.number().min(1, "Rating must be at least 1").max(5, "Rating cannot exceed 5"),
        comment: z.string().max(1000).optional()
    })
});