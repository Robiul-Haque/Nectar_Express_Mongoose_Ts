import mongoose from "mongoose";
import { z } from "zod";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid category id" });

export const createCategorySchema = z.object({
    body: z.object({
        name: z.string().min(2).max(100),
        description: z.string().max(500).optional(),
        isFeatured: z.coerce.boolean().optional(),
        sortOrder: z.coerce.number().optional()
    })
});

export const getAllCategoriesSchema = z.object({
    query: z
        .object({
            search: z.string().trim().min(1, "Search cannot be empty").max(100, "Search too long").optional(),
            page: z.string().optional().transform((val) => (val ? Number(val) : 1)).refine((val) => !isNaN(val) && val > 0, { message: "Page must be a positive number" }),
            limit: z.string().optional().transform((val) => (val ? Number(val) : 10)).refine((val) => !isNaN(val) && val > 0 && val <= 100, { message: "Limit must be between 1 and 100" }),
            active: z.string().optional().transform((val) => { if (val === undefined) return undefined; return val.toLowerCase() === "true" })
        })
        .strict()
});

export const updateCategorySchema = z.object({
    params: z.object({
        id: z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" })
    }),
    body: z.object({
        name: z.string().min(2).max(100).optional(),
        description: z.string().max(500).optional(),
        isActive: z.coerce.boolean().optional(),
        isFeatured: z.coerce.boolean().optional(),
        sortOrder: z.coerce.number().optional()
    })
});

export const deleteCategorySchema = z.object({
    params: z.object({ id: objectIdSchema }).strict()
});