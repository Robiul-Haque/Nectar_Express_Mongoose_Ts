import { Request, Response, NextFunction } from "express";
import { getCache, setCache } from "../utils/redis";
import logger from "../utils/logger";

/**
 * Reusable Express middleware to cache GET requests.
 * Intercepts res.json to capture response bodies and store them in Redis.
 * 
 * @param ttlSeconds - Cache Time-To-Live in seconds
 */
export const cacheMiddleware = (ttlSeconds: number = 300) => {
    return async (req: Request, res: Response, next: NextFunction) => {
        // Cache only GET requests
        if (req.method !== "GET") {
            return next();
        }

        // Create a cache key using the full original URL path and query parameters
        const cacheKey = `cache:${req.originalUrl}`;

        try {
            const cachedData = await getCache(cacheKey);
            if (cachedData) {
                const parsedBody = JSON.parse(cachedData);
                // Return cached response directly
                return res.status(200).json(parsedBody);
            }

            // Intercept res.json to capture the response body on a cache miss
            const originalJson = res.json;
            res.json = function (body: any): Response {
                // Restore the original res.json function
                res.json = originalJson;

                // Cache only successful responses (2xx)
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    setCache(cacheKey, JSON.stringify(body), ttlSeconds).catch((err) => {
                        logger.error(`[Redis Cache Middleware] Failed to write key ${cacheKey}: ${err}`);
                    });
                }

                return originalJson.call(this, body);
            };

            next();
        } catch (error) {
            logger.error(`[Redis Cache Middleware] Error processing cache: ${error}`);
            next(); // Gracefully fallback to next middleware/controller on failure
        }
    };
};
