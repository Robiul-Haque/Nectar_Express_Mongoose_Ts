import { z } from "zod";

export const createPaymentIntentSchema = z.object({
    body: z.object({
        shippingAddress: z.object({
            address: z.string().min(1, "Address is required"),
            city: z.string().min(1, "City is required"),
            country: z.string().min(1, "Country is required"),
            phone: z.string().min(11).max(15).regex(/^[0-9+]+$/, "Invalid phone number")
        })
    })
});