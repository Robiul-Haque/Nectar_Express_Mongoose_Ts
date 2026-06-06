import { z } from "zod";
import mongoose from "mongoose";

export const objectId = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid id" });

export const createOrderSchema = z.object({
    body: z.object({
        paymentIntentId: z.string().min(10),
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
        limit: z.string().optional().transform((val) => (val ? parseInt(val) : 10)),
        search: z.string().optional(),
        orderStatus: z.enum(["pending", "confirmed", "shipped", "delivered", "cancelled", "All Orders"]).optional()
    })
});

export const updateStatusSchema = z.object({
    params: z.object({ id: objectId }),
    body: z.object({
        orderStatus: z.enum(["pending", "confirmed", "shipped", "delivered", "cancelled"])
    })
});

export const deleteOrderSchema = z.object({
    params: z.object({ id: objectId })
});