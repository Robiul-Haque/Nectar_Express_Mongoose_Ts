import { z } from "zod";

export const locationSchema = z.object({
    body: z.object({
        location: z
            .object({
                latitude: z.number({ message: "Latitude must be a number" }).min(-90, "Latitude must be between -90 and 90").max(90, "Latitude must be between -90 and 90"),
                longitude: z.number({ message: "Longitude must be a number" }).min(-180, "Longitude must be between -180 and 180").max(180, "Longitude must be between -180 and 180"),
                country: z.string({ message: "Country is required" }).trim().min(1, "Country cannot be empty").max(100, "Country name is too long"),
                city: z.string({ message: "City is required" }).trim().min(1, "City cannot be empty").max(100, "City name is too long")
            })
            .strict()
    }).strict()
});

export const updateProfileSchema = z.object({
    name: z.string().trim().min(2, "Name must be at least 2 characters").max(30, "Name cannot exceed 30 characters").optional(),
    email: z.string().trim().email("Please provide a valid email address").max(100, "Email cannot exceed 100 characters").optional()
});

export const toggleUserStatusSchema = z.object({
    params: z.object({
        id: z.string({ message: "User ID is required" }).regex(/^[0-9a-fA-F]{24}$/, "Invalid User ID format")
    }),
    body: z.object({
        isActive: z.boolean({ message: "isActive status is required" })
    })
});

export const updateAdminProfileSchema = z.object({
    body: z.object({
        name: z.string().trim().min(2, "Name must be at least 2 characters").max(50, "Name cannot exceed 50 characters").optional(),
        password: z
            .string()
            .min(6, "Password must be at least 6 characters long")
            .regex(/[A-Z]/, "Password must contain at least one capital letter")
            .regex(/[a-z]/, "Password must contain at least one small letter")
            .regex(/[0-9]/, "Password must contain at least one number")
            .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character")
            .optional()
    }).strict()
});