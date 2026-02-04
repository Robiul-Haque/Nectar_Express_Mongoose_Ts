import { z } from 'zod';

export const registerUserSchema = z.object({
    name: z.string().min(2, { message: 'Name is required' }),
    email: z.email(),
    password: z.string().min(6, { message: 'Password must be at least 6 characters' }).optional(),
    phone: z.string().optional(),
    avatar: z.url().optional(),
    provider: z.enum(['google', 'facebook', 'email']).default('email'),
});

export const loginUserSchema = z.object({
    email: z.string().email(),
    password: z.string().min(6).optional(),
    provider: z.enum(['google', 'facebook', 'email']),
});

export type RegisterUserInput = z.infer<typeof registerUserSchema>;
export type LoginUserInput = z.infer<typeof loginUserSchema>;