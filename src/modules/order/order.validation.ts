import { z } from "zod";

export const createOrderSchema = z.object({
    body: z.object({
        shippingAddress: z.object({
            address: z.string().min(5).max(200),
            city: z.string().min(2).max(100),
            country: z.string().min(2).max(100),
            phone: z.string().min(8).max(20)
        })
    }).strict()
});