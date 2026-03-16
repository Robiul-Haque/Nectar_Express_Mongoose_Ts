import { z } from "zod";
import mongoose from "mongoose";

const objectId = z.string().refine((v) => mongoose.Types.ObjectId.isValid(v), { message: "Invalid id" });

const itemSchema = z.object({
    productId: objectId,
    quantity: z.coerce.number().min(1).max(20)
});

export const cartBulkSchema = z.object({
    body: z.object({
        add: z.array(itemSchema).optional(),
        update: z.array(itemSchema).optional(),
        remove: z.array(objectId).optional()
    }).strict()
});

export const getAllCartsSchema = z.object({
    query: z.object({
        page: z.coerce.number().min(1).optional().default(1),
        limit: z.coerce.number().min(1).max(100).optional().default(10)
    }).strict()
});

export const adminUpdateCartSchema = z.object({
    params: z.object({
        cartId: objectId
    }),
    body: z.object({
        productId: objectId,
        action: z.enum(["increment", "decrement", "remove"])
    }).strict()
});