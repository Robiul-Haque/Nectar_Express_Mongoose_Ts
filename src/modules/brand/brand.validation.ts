import { z } from "zod";

export const createBrandSchema = z.object({
    body: z.object({
        name: z.string().trim().min(1, "Brand name is required").max(100, "Name cannot exceed 100 characters")
    })
});

export const updateBrandSchema = z.object({
    body: z.object({
        name: z.string().trim().min(1, "Brand name is required").max(100, "Name cannot exceed 100 characters").optional(),
        isActive: z.string().optional().transform((val) => {
            if (val === undefined) return undefined;
            return val.toLowerCase() === "true";
        })
    })
});