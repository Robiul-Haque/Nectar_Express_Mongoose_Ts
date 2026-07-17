import { Request } from "express";

/**
 * Extracts the real client IP from the request.
 * Handles reverse-proxy forwarded headers (nginx, Cloudflare, etc.)
 */
export const getClientIp = (req: Request): string => {
    const forwarded = req.headers["x-forwarded-for"];
    if (forwarded) {
        const ips = Array.isArray(forwarded) ? forwarded[0] : forwarded;
        // Take the first IP (real client IP when behind proxy)
        return ips.split(",")[0].trim();
    }
    return (
        (req.headers["x-real-ip"] as string) ||
        req.socket?.remoteAddress ||
        "unknown"
    );
};

/**
 * Extracts the User-Agent string from the request.
 */
export const getUserAgent = (req: Request): string => {
    return req.headers["user-agent"] || "unknown";
};

/**
 * Extracts app version from custom header (mobile app should send X-App-Version).
 */
export const getAppVersion = (req: Request): string | null => {
    return (req.headers["x-app-version"] as string) || null;
};

/**
 * Extracts platform from custom header (mobile app should send X-Platform: android|ios|web).
 */
export const getRequestPlatform = (req: Request): "android" | "ios" | "web" | "unknown" => {
    const platform = (req.headers["x-platform"] as string)?.toLowerCase();
    if (platform === "android" || platform === "ios" || platform === "web") return platform;
    return "unknown";
};

/**
 * Extracts device ID from custom header (mobile app should send X-Device-Id).
 */
export const getDeviceId = (req: Request): string | null => {
    return (req.headers["x-device-id"] as string) || null;
};

/**
 * Bundles all request context into a single object for LoginHistory recording.
 */
export const getRequestContext = (req: Request) => ({
    ip: getClientIp(req),
    userAgent: getUserAgent(req),
    appVersion: getAppVersion(req),
    platform: getRequestPlatform(req),
    deviceId: getDeviceId(req)
});
