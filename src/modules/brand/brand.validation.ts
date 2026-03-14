import mongoose from "mongoose";
import { z } from "zod";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid brand id" });

export const createBrandSchema = z.object({
    body: z.object({
        name: z.string().trim().min(1, "Brand name is required").max(100, "Name cannot exceed 100 characters")
    })
});

export const getAllBrandsSchema = z.object({
    query: z
        .object({
            page: z.string().optional().transform((v) => (v ? Number(v) : 1)).refine((v) => Number.isInteger(v) && v > 0, { message: "Page must be a positive integer" }),
            limit: z.string().optional().transform((v) => (v ? Number(v) : 10)).refine((v) => Number.isInteger(v) && v > 0 && v <= 100, { message: "Limit must be between 1 and 100" }),
            search: z.string().trim().min(1, "Search cannot be empty").optional(),
            active: z.enum(["true", "false"]).optional(),
        })
        .strict()
});

export const getSingleBrandSchema = z.object({
    params: z.object({ id: objectIdSchema }).strict()
});

export const updateBrandSchema = z.object({
    params: z.object({ id: objectIdSchema }).strict(),
    body: z.object({
        name: z.string().trim().min(1, "Brand name is required").max(100, "Name cannot exceed 100 characters").optional(),
        isActive: z.string().optional().transform((val) => {
            if (val === undefined) return undefined;
            return val.toLowerCase() === "true";
        })
    })
});

export const deleteBrandSchema = z.object({
    params: z.object({ id: objectIdSchema }).strict()
});