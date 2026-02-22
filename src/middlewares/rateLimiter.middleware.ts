import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { Request } from 'express';

export const globalRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => ipKeyGenerator(req as any) ?? 'unknown-ip',
    message: {
        success: false,
        message: 'Too many requests. Please try again later.',
    },
});

export const authRateLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    keyGenerator: (req: Request): string => {
        const key = ipKeyGenerator(req as any);
        return key ?? 'unknown-ip';
    },
    message: {
        success: false,
        message: 'Too many authentication attempts. Please wait 10 minutes and try again.',
    },
});

export const refreshTokenLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    keyGenerator: (req: Request): string => {
        const key = ipKeyGenerator(req as any);
        return key ?? 'unknown-ip';
    },
    message: {
        success: false,
        message: 'Too many token refresh attempts. Please try again later.',
    },
});
