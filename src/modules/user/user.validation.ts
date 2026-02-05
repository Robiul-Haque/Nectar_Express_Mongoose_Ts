import { z } from 'zod';

export const emailRegisterSchema = z.object({
    name: z.string().min(2),
    email: z.email(),
    password: z.string().min(6),
});

export const emailLoginSchema = z.object({
    email: z.email(),
    password: z.string().min(6),
});

export const googleLoginSchema = z.object({
    idToken: z.string(),
});

export const facebookLoginSchema = z.object({
    accessToken: z.string(),
});