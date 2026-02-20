import z from "zod";

const passwordSchema = z
    .string()
    .min(6, "Password must be at least 6 characters long")
    .regex(/[A-Z]/, "Password must contain at least one capital letter")
    .regex(/[a-z]/, "Password must contain at least one small letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

export const emailRegisterSchema = z.object({
    name: z.string().min(2, "Name must be at least 2 characters"),
    email: z.email("Invalid email address"),
    password: passwordSchema,
    role: z.enum(["user", "admin"]).optional(),
});

export const otpVerifySchema = z.object({
    email: z.email(),
    otp: z.string().length(6, "OTP must be 6 characters long"),
});

export const emailLoginSchema = z.object({
    email: z.email("Invalid email address").trim().toLowerCase(),
    password: passwordSchema,
    fcmToken: z.string().min(10, "Invalid FCM token").optional(),
    platform: z.enum(["android", "ios", "web"]).optional(),
    deviceId: z.string().max(200).optional().nullable()
})
    .superRefine((data, ctx) => {
        if (data.fcmToken && !data.platform) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: "Platform is required when fcmToken is provided",
                path: ["platform"]
            });
        }
    });

export const forgotPasswordSchema = z.object({
    email: z.string().email("Invalid email address")
});

export const resetPasswordSchema = z.object({
    email: z.email("Invalid email address"),
    otp: z.string().min(6, "Invalid OTP").max(6, "Invalid OTP"),
    newPassword: passwordSchema
});

export const googleLoginSchema = z.object({
    idToken: z.string(),
});

export const facebookLoginSchema = z.object({
    accessToken: z.string(),
});