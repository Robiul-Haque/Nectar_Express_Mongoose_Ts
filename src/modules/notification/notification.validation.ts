import { z } from "zod";

export const registerDeviceSchema = z.object({
    body: z.object({
        token: z.string().min(10),
        platform: z.enum(["android", "ios", "web"]),
        deviceId: z.string().optional().nullable()
    })
});

export const toggleNotificationSchema = z.object({
    body: z.object({
        enabled: z.boolean()
    })
});