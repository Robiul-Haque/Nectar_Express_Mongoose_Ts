import { z } from "zod";
import mongoose from "mongoose";

const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid ObjectId" });

export const createProductSchema = z.object({
    body: z.object({
        name: z.string().min(1).max(150),
        description: z.string().max(2000).optional(),
        measurement: z.object({
            value: z.coerce.number().min(0),
            unit: z.enum(["kg", "g", "pc"])
        }),
        price: z.coerce.number().min(0),
        discountPrice: z.coerce.number().min(0).optional(),
        stock: z.coerce.number().min(0).optional(),
        category: objectIdSchema,
        brand: objectIdSchema,
        nutrition: z.string().max(1000).optional(),
        isFeatured: z.coerce.boolean().optional(),
        isActive: z.coerce.boolean().optional()
    })
        .refine(
            (data) => {
                if (data.discountPrice === undefined) return true;
                return data.discountPrice < data.price;
            },
            {
                message: "Discount price must be less than price",
                path: ["discountPrice"]
            }
        )
});

export const updateProductSchema = z.object({
    params: z.object({
        id: objectIdSchema
    }),
    body: z.object({
        name: z.string().min(1).max(150).optional(),
        description: z.string().max(2000).optional(),
        measurement: z.object({
            value: z.coerce.number().min(0).optional(),
            unit: z.enum(["kg", "g", "pc"]).optional()
        }).optional(),
        price: z.coerce.number().min(0).optional(),
        discountPrice: z.coerce.number().min(0).optional(),
        stock: z.coerce.number().min(0).optional(),
        category: objectIdSchema.optional(),
        brand: objectIdSchema.optional(),
        nutrition: z.string().max(1000).optional(),
        isFeatured: z.coerce.boolean().optional(),
        isActive: z.coerce.boolean().optional()
    })
})