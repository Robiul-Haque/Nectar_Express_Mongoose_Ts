import { z } from "zod";

export const createBrandSchema = z.object({
    name: z.string().trim().min(1, "Brand name is required").max(100, "Name cannot exceed 100 characters"),
});

export const updateBrandSchema = z.object({
    name: z.string().trim().min(1).max(100).optional(),
    isActive: z.boolean().optional()
});