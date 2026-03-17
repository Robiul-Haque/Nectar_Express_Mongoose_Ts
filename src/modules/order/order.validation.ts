import { z } from "zod";
import mongoose from "mongoose";

export const objectId = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid id" });

export const createOrderSchema = z.object({
    body: z.object({
        shippingAddress: z.object({
            address: z.string().min(5),
            city: z.string().min(2),
            country: z.string().min(2),
            phone: z.string().min(8)
        })
    })
});

export const getAllOrderSchema = z.object({
    query: z.object({
        page: z.string().optional().transform((val) => (val ? parseInt(val) : 1)),
        limit: z.string().optional().transform((val) => (val ? parseInt(val) : 10))
    })
});

export const updateStatusSchema = z.object({
    params: z.object({ id: objectId }),
    body: z.object({
        status: z.enum(["confirmed", "shipped", "delivered", "cancelled"])
    })
});

export const deleteOrderSchema = z.object({
    params: z.object({ id: objectId })
});