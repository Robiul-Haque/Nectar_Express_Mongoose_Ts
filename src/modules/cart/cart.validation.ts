import { z } from "zod";
import mongoose from "mongoose";

export const objectIdSchema = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), {message: "Invalid ObjectId"});

export const cartItemSchema = z.object({
    product: objectIdSchema,
    quantity: z.number().int().min(1, "Quantity must be at least 1").default(1),
    price: z.number().nonnegative("Price must be >= 0"),
    variant: z.string().optional()
});

export const createCartSchema = z.object({
    body: z.object({
        items: z.array(cartItemSchema).min(1, "Cart must have at least one item")
    })
});

export const updateCartItemSchema = z.object({
    body: z.object({
        product: objectIdSchema,
        quantity: z.number().int().min(0, "Quantity must be >= 0")
    })
});