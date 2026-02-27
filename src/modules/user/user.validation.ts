import z from "zod";

export const updateProfileSchema = z.object({
    name: z.string().trim().min(2, "Name must be at least 2 characters").max(30, "Name cannot exceed 30 characters").optional()
});