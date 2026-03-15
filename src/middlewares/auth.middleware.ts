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

const authenticate = (requiredRoles?: Role[]) =>
    catchAsync(async (req: Request, res: Response, next: NextFunction) => {
        const authHeader = req.headers.authorization;

        const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7).trim() : authHeader?.trim() || req.cookies?.accessToken;

        if (!token) return sendResponse(res, status.UNAUTHORIZED, "Access token missing");

        let decoded: JwtPayload;

        try {
            decoded = jwt.verify(token, env.JWT_ACCESS_TOKEN, { issuer: "nectar-api" }) as JwtPayload;
        } catch (error) {
            if (error instanceof TokenExpiredError) console.warn("[Auth] Token expired:", error.expiredAt);
            if (error instanceof JsonWebTokenError) console.warn("[Auth] Invalid token:", error.message);

            return sendResponse(res, status.UNAUTHORIZED, "Invalid or expired token");
        }

        const user = await User.findById(decoded.sub).select("role refreshTokenVersion isVerified").lean<{ role: Role; refreshTokenVersion: number; isVerified: boolean }>();
        if (!user) return sendResponse(res, status.UNAUTHORIZED, "User not found");

        // Token version check
        if (user.refreshTokenVersion !== decoded.v) return sendResponse(res, status.UNAUTHORIZED, "Token has been invalidated. Please login again");

        // Role mismatch (security protection)
        if (decoded.role !== user.role) return sendResponse(res, status.UNAUTHORIZED, "Token role mismatch");

        // Email verification (skip admin)
        if (!user.isVerified && user.role !== "admin") return sendResponse(res, status.FORBIDDEN, "Please verify your email to continue");

        // ROLE BASED ACCESS CONTROL
        if (requiredRoles?.length && !requiredRoles.includes(user.role)) return sendResponse(res, status.FORBIDDEN, `Access denied. The role '${user.role}' is not permitted to access this API. Required role: ${requiredRoles.join(" or ")}`);

        // Attach user
        req.user = {
            sub: decoded.sub,
            role: user.role,
            v: decoded.v
        };

        next();
    });

export default authenticate;