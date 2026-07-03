import Redis from "ioredis";
import cluster from "cluster";
import { env } from "../config/env";
import logger from "./logger";

let redis: Redis | null = null;

try {
    if (env.REDIS_URL) {
        redis = new Redis(env.REDIS_URL, {
            maxRetriesPerRequest: 3, // Avoid blocking indefinitely if connection fails
            retryStrategy: (times) => Math.min(times * 100, 3000),
            reconnectOnError: () => true
        });

        redis.on("connect", () => {
            if (!cluster.isWorker || cluster.worker?.id === 1) {
                logger.info("⚡ Redis connected successfully");
            }
        });

        redis.on("error", (err: any) => {
            logger.error(`❌ Redis connection failed. API will fallback to Database: ${err.message || err}`);
        });
    } else {
        if (!cluster.isWorker || cluster.worker?.id === 1) {
            logger.warn("⚠️ REDIS_URL is not defined. Caching is disabled.");
        }
    }
} catch (error) {
    logger.error(`❌ Redis initialization failed. API will fallback to Database: ${error}`);
}

/**
 * Retrieve item from cache
 */
export const getCache = async (key: string): Promise<string | null> => {
    if (!redis) return null;
    try {
        return await redis.get(key);
    } catch (err) {
        logger.warn(`[Redis] getCache failed for key ${key}: ${err}`);
        return null;
    }
};

/**
 * Save item in cache with TTL
 */
export const setCache = async (key: string, value: string, ttlSeconds: number = 3600): Promise<void> => {
    if (!redis) return;
    try {
        await redis.set(key, value, "EX", ttlSeconds);
    } catch (err) {
        logger.warn(`[Redis] setCache failed for key ${key}: ${err}`);
    }
};

/**
 * Delete specific key from cache
 */
export const deleteCache = async (key: string): Promise<void> => {
    if (!redis) return;
    try {
        await redis.del(key);
    } catch (err) {
        logger.warn(`[Redis] deleteCache failed for key ${key}: ${err}`);
    }
};

/**
 * Delete keys matching a pattern using non-blocking SCAN stream
 */
export const deletePattern = async (pattern: string): Promise<void> => {
    if (!redis) return;
    try {
        const stream = redis.scanStream({ match: pattern, count: 100 });
        const keysToDelete: string[] = [];

        for await (const resultKeys of stream) {
            keysToDelete.push(...resultKeys);
        }

        if (keysToDelete.length > 0) {
            for (let i = 0; i < keysToDelete.length; i += 500) {
                const chunk = keysToDelete.slice(i, i + 500);
                await redis.del(...chunk);
            }
        }
    } catch (err) {
        logger.warn(`[Redis] deletePattern failed for pattern ${pattern}: ${err}`);
    }
};

/**
 * Gracefully disconnect main Redis client
 */
export const closeMainRedis = async (): Promise<void> => {
    if (redis) {
        try {
            await redis.quit();
            logger.info("Main Redis connection closed.");
        } catch (err) {
            logger.warn(`Error closing main Redis connection: ${err}`);
        }
    }
};

export default redis;
