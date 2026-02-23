import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
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
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer "))  return sendResponse(res, status.UNAUTHORIZED, "Access token missing");

        const token = authHeader.split(" ")[1];

        let decoded: JwtPayload;

        try {
            decoded = jwt.verify(token, env.JWT_ACCESS_TOKEN, {issuer: "nectar-api",audience: "nectar-admin",}) as JwtPayload;
        } catch {
            return sendResponse(res, status.UNAUTHORIZED, "Invalid or expired token");
        }

        // Optimized DB lookup
        const user = await User.findById(decoded.sub).select("role refreshTokenVersion isVerified").lean();

        if (!user) return sendResponse(res, status.UNAUTHORIZED, "User not found");

        // Token version validation
        if (user.refreshTokenVersion !== decoded.v) return sendResponse(res, status.UNAUTHORIZED, "Token invalidated");

        // Account verification check
        // Admin bypass allowed (remove role condition if not needed)
        if (!user.isVerified && user.role !== "admin")  return sendResponse(res, status.FORBIDDEN, "Account not verified");

        // Role-based authorization
        if (requiredRoles && !requiredRoles.includes(user.role as Role)) return sendResponse(res, status.FORBIDDEN, "Access denied");

        req.user = {
            sub: decoded.sub,
            role: user.role as Role,
            v: decoded.v,
        };

        next();
    });