import { z } from "zod";
import mongoose from "mongoose";

export const objectId = z.string().refine((val) => mongoose.Types.ObjectId.isValid(val), { message: "Invalid id" });

export const updateLocationSchema = z.object({
    body: z.object({
        latitude: z.number().min(-90).max(90),
        longitude: z.number().min(-180).max(180),
        bearing: z.number().min(0).max(360).optional(),
        speed: z.number().nonnegative().optional(),
        orderId: objectId.optional()
    })
});

export const assignDriverSchema = z.object({
    body: z.object({
        orderId: objectId,
        driverId: objectId,
        startLocation: z.object({
            latitude: z.number().min(-90).max(90),
            longitude: z.number().min(-180).max(180)
        }).optional(),
        deliveryLocation: z.object({
            latitude: z.number().min(-90).max(90),
            longitude: z.number().min(-180).max(180)
        }).optional()
    })
});

export const updateTrackingStatusSchema = z.object({
    params: z.object({
        orderId: objectId
    }),
    body: z.object({
        status: z.enum(["assigned", "at_store", "in_transit", "delivered"]),
        estimatedDeliveryTime: z.string().datetime().optional()
    })
});

export const toggleActiveStatusSchema = z.object({
    body: z.object({
        isActive: z.boolean()
    })
});

export const getNearbyDriversSchema = z.object({
    query: z.object({
        latitude: z.string().transform((val) => parseFloat(val)),
        longitude: z.string().transform((val) => parseFloat(val)),
        maxDistance: z.string().optional().transform((val) => (val ? parseInt(val) : 5000)) // meters, default 5km
    })
});
