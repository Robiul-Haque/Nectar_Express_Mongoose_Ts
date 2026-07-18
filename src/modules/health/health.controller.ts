import { Request, Response } from "express";
import mongoose from "mongoose";
import status from "http-status";
import redis from "../../utils/redis";
import { env } from "../../config/env";
import catchAsync from "../../utils/catchAsync";

/**
 * Health check controller to verify system readiness.
 * Checks MongoDB and Redis connection status.
 */
export const checkHealth = catchAsync(async (req: Request, res: Response) => {
    const isDbConnected = mongoose.connection.readyState === 1;
    const isRedisConnected = redis ? redis.status === 'ready' : true;
    const isHealthy = isDbConnected && isRedisConnected;

    const healthData = {
        status: isHealthy ? 'UP' : 'DOWN',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        pid: process.pid,
        services: {
            database: isDbConnected ? 'connected' : 'disconnected',
            redis: env.REDIS_URL ? (redis ? redis.status : 'disconnected') : 'disabled',
        },
    };

    res.status(isHealthy ? status.OK : status.SERVICE_UNAVAILABLE).json(healthData);
});
