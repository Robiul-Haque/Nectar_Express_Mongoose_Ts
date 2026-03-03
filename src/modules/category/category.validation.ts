import { z } from "zod";

export const createCategorySchema = z.object({
    body: z.object({
        name: z.string().min(2).max(100),
        description: z.string().max(500).optional(),
        isFeatured: z.coerce.boolean().optional(),
        sortOrder: z.coerce.number().optional(),
    })
});

export const updateCategorySchema = z.object({
    body: z.object({
        name: z.string().min(2).max(100).optional(),
        description: z.string().max(500).optional(),
        isActive: z.coerce.boolean().optional(),
        isFeatured: z.coerce.boolean().optional(),
        sortOrder: z.coerce.number().optional(),
    })
});