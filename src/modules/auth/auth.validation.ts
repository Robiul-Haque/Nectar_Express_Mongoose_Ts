import { z } from "zod";

const passwordSchema = z
    .string()
    .min(6, "Password must be at least 6 characters long")
    .regex(/[A-Z]/, "Password must contain at least one capital letter")
    .regex(/[a-z]/, "Password must contain at least one small letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

export const emailRegisterSchema = z.object({
    name: z.string().trim().min(2, "Name must be at least 2 characters").max(30, "Name cannot exceed 30 characters"),
    email: z.string().trim().toLowerCase().email("Invalid email address"),
    password: passwordSchema,
    role: z.enum(["user", "admin"]).optional()
});

export const otpVerifySchema = z.object({
    email: z.string().trim().toLowerCase().email("Invalid email address"),
    otp: z.string().length(6, "OTP must be 6 characters long")
});

export const emailLoginSchema = z.object({
    body: z
        .object({
            email: z.string({ message: "Email is required", }).trim().toLowerCase().email("Invalid email address"),
            password: z.string({ message: "Password is required" }).min(1, "Password is required"),
        })
        .strict()
});

export const refreshTokenSchema = z
    .object({
        refreshToken: z.string().min(1, "Refresh token not found").min(20, "Invalid refresh token format"),
    })
    .strict();

export const forgotPasswordSchema = z.object({
    email: z.string().trim().toLowerCase().email("Invalid email address")
});

export const resetPasswordSchema = z.object({
    email: z.string().trim().toLowerCase().email("Invalid email address"),
    otp: z.string().length(6, "Invalid OTP"),
    newPassword: passwordSchema
});

export const googleLoginSchema = z
    .object({
        idToken: z.string().min(1),
        fcmToken: z.string().optional(),
        platform: z.enum(["android", "ios", "web"]).optional(),
        deviceId: z.string().nullable().optional()
    })
    .strict()
    .superRefine((data, ctx) => {
        if (data.fcmToken && !data.platform) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: "Platform is required when fcmToken is provided",
                path: ["platform"]
            });
        }
    });

export const facebookLoginSchema = z
    .object({
        accessToken: z.string().min(1, "Facebook access token is required").min(10, "Invalid Facebook access token"),
        fcmToken: z.string().min(1, "FCM token cannot be empty").optional(),
        platform: z.enum(["android", "ios", "web"], { message: "Platform must be android, ios, or web" }).optional(),
        deviceId: z.string().nullable().optional()
    })
    .strict()
    .superRefine((data, ctx) => {
        if (data.fcmToken && !data.platform) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: "Platform is required when fcmToken is provided",
                path: ["platform"],
            });
        }
    });