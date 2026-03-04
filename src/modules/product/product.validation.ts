import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId", });

export const createProductSchema = z.object({
    body: z.object({
        name: z.string().min(1).max(150),
        description: z.string().max(2000).optional(),
        measurement: z.object({
            value: z.number().min(0),
            unit: z.enum(["kg", "g", "pc"])
        }),
        price: z.number().min(0),
        stock: z.number().min(0).optional(),
        category: objectIdSchema,
        brand: objectIdSchema,
        nutrition: z.string().max(1000).optional(),
        isFeatured: z.boolean().optional(),
        isActive: z.boolean().optional(),
    })
});

export const updateProductSchema = createProductSchema.partial();