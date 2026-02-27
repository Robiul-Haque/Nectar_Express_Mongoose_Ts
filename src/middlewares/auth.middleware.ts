import { Request, Response, NextFunction } from "express";
import jwt, { TokenExpiredError, JsonWebTokenError } from "jsonwebtoken";
import status from "http-status";
import User from "../modules/user/user.model";
import { env } from "../config/env";
import sendResponse from "../utils/sendResponse";
import catchAsync from "../utils/catchAsync";

type Role = "user" | "admin";

interface JwtPayload {
    sub: string;
    role: Role;
    v: number;
    iat: number;
    exp: number;
}

declare global {
    namespace Express {
        interface Request {
            user?: {
                sub: string;
                role: Role;
                v: number;
            };
        }
    }
}

export const authenticate = (requiredRoles?: Role[]) =>
    catchAsync(async (req: Request, res: Response, next: NextFunction) => {

        let token: string | undefined;

        if (req.headers.authorization) {
            const authHeader = req.headers.authorization;
            token = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : authHeader.trim();
        }

        // Fallback: Cookie (development/browser support)
        if (!token && req.cookies?.accessToken) token = req.cookies.accessToken;
        if (!token) return sendResponse(res, status.UNAUTHORIZED, "Access token missing");

        let decoded: JwtPayload;

        try {
            decoded = jwt.verify(token, env.JWT_ACCESS_TOKEN, { issuer: "nectar-api", audience: "nectar-users" }) as JwtPayload;
        } catch (error) {
            // Enhanced logging for debugging
            if (error instanceof TokenExpiredError) {
                console.warn("[Auth] Token expired at:", error.expiredAt);
            } else if (error instanceof JsonWebTokenError) {
                console.warn("[Auth] Invalid token:", error.message);
            }
            return sendResponse(res, status.UNAUTHORIZED, "Invalid or expired token");
        }

        const user = await User.findById(decoded.sub)
            .select("role refreshTokenVersion isVerified")
            .lean<{ role: Role; refreshTokenVersion: number; isVerified: boolean }>();

        if (!user) return sendResponse(res, status.UNAUTHORIZED, "User not found");

        // Token version check (logout from all devices)
        if (user.refreshTokenVersion !== decoded.v) return sendResponse(res, status.UNAUTHORIZED, "Token has been invalidated. Please login again");

        // Email verification check (skip for admin)
        if (!user.isVerified && user.role !== "admin") return sendResponse(res, status.FORBIDDEN, "Please verify your email to continue");

        // Role-based access control
        if (requiredRoles && requiredRoles.length > 0) {
            if (!requiredRoles.includes(user.role)) return sendResponse(res, status.FORBIDDEN, `Access denied. Required role: ${requiredRoles.join(" or ")}`);
        }

        req.user = {
            sub: decoded.sub,
            role: user.role,
            v: decoded.v,
        };

        next();
    });