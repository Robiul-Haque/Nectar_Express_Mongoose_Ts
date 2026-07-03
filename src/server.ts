import mongoose from 'mongoose';
import cluster from 'cluster';
import os from 'os';
import dns from 'dns';
import { env } from './config/env';
import logger from './utils/logger';
import seedAdmin from './seeders/adminSeeder';
import { verifySMTP } from './utils/sendOtpEmail';
import { server, io, closeSocketAdapterClients } from './app';
import { closeMainRedis } from './utils/redis';

// Set default DNS resolution order to IPv4 first to prevent EAI_AGAIN DNS timeouts in Docker
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}

// Global Process Error Handlers - Register early before any async operations start
process.on('unhandledRejection', (reason: unknown) => {
    logger.error(`❌ Unhandled Rejection: ${reason instanceof Error ? reason.stack || reason.message : String(reason)}`);
});

process.on('uncaughtException', (error: Error) => {
    logger.error(`❌ Uncaught Exception: ${error.stack || error.message}`);
});

// Database connection with exponential backoff retry strategy and lifecycle listeners
async function connectDBWithRetry(maxRetries = 5, initialDelayMs = 2000): Promise<void> {
    const dbUrl = env.DB_URL;
    if (!dbUrl) {
        logger.error('❌ DB_URL is not defined in environment variables');
        process.exit(1);
    }

    // Mongoose Connection Event Listeners
    mongoose.connection.on('error', (err) => {
        logger.error(`❌ Mongoose Connection Error: ${err.message}`);
    });

    mongoose.connection.on('disconnected', () => {
        logger.warn('⚠️ Mongoose Connection Disconnected');
    });

    mongoose.connection.on('reconnected', () => {
        logger.info('✅ Mongoose Connection Reestablished');
    });

    let delay = initialDelayMs;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            await mongoose.connect(dbUrl, {
                maxPoolSize: 50,
                minPoolSize: 5,
                serverSelectionTimeoutMS: 5000,
                socketTimeoutMS: 45000,
                autoIndex: env.NODE_ENV !== 'production',
            });
            logger.info('✅ DB connected successfully');
            return;
        } catch (err) {
            const errorMsg = err instanceof Error ? err.message : String(err);
            logger.error(`❌ DB connection attempt ${attempt}/${maxRetries} failed: ${errorMsg}`);
            if (attempt === maxRetries) {
                logger.error(`❌ Critical: Unable to connect to MongoDB after ${maxRetries} attempts.`);
                process.exit(1);
            }
            logger.info(`Retrying DB connection in ${delay / 1000}s...`);
            await new Promise((resolve) => setTimeout(resolve, delay));
            delay *= 2;
        }
    }
}

async function bootstrap() {
    // 1. Wait for Database connection to establish before accepting HTTP traffic
    await connectDBWithRetry();

    // 2. Perform admin seeding and SMTP verification in non-cluster mode
    if (!env.USE_CLUSTER) {
        await seedAdmin();
        if (env.NODE_ENV !== 'production') {
            verifySMTP();
        }
    }

    // 3. Start HTTP server only after DB is verified ready
    const newServer = server.listen(env.PORT, '0.0.0.0', () => {
        logger.info(`🚀 Worker ${process.pid} running on port ${env.PORT}`);
    });

    // 4. Graceful shutdown sequence: Socket.IO -> HTTP Server -> Redis Clients -> Mongoose -> Exit
    let isShuttingDown = false;

    const handleShutdown = async (signal: string) => {
        if (isShuttingDown) return;
        isShuttingDown = true;
        logger.warn(`Worker ${process.pid} received ${signal}. Initiating graceful shutdown...`);

        // 10-second unref'd fallback safety timer
        const forceExitTimeout = setTimeout(() => {
            logger.error(`Worker ${process.pid} forced to exit after 10s shutdown timeout`);
            process.exit(1);
        }, 10000);
        forceExitTimeout.unref();

        try {
            // Close Socket.IO server
            if (io) {
                logger.info('Closing Socket.IO connections...');
                await new Promise<void>((resolve) => io.close(() => resolve()));
            }

            // Stop HTTP server from accepting new connections
            logger.info('Closing HTTP server...');
            await new Promise<void>((resolve, reject) => {
                newServer.close((err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });

            // Close Redis connections
            logger.info('Closing Redis connections...');
            await closeSocketAdapterClients();
            await closeMainRedis();

            // Disconnect Mongoose
            logger.info('Disconnecting Mongoose...');
            await mongoose.disconnect();

            logger.info(`✅ Worker ${process.pid} graceful shutdown complete.`);
            process.exit(0);
        } catch (err) {
            logger.error(`❌ Error during graceful shutdown: ${err instanceof Error ? err.message : String(err)}`);
            process.exit(1);
        }
    };

    process.on('SIGTERM', () => handleShutdown('SIGTERM'));
    process.on('SIGINT', () => handleShutdown('SIGINT'));
}

async function primaryBootstrap() {
    const numCPUs = os.cpus().length;
    logger.info(`⚡ Primary cluster process ${process.pid} is running. Performing initial seeding...`);

    try {
        await connectDBWithRetry();
        await seedAdmin();
        if (env.NODE_ENV !== 'production') {
            verifySMTP();
        }
        await mongoose.disconnect();
        logger.info(`✅ Primary process initialization complete. Spawning ${numCPUs} worker processes...`);
    } catch (err) {
        logger.error(`❌ Primary process initialization failed: ${err}`);
        process.exit(1);
    }

    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker) => {
        if (!worker.exitedAfterDisconnect) {
            logger.warn(`⚠️ Worker process ${worker.process.pid} died. Spawning a replacement...`);
            cluster.fork();
        }
    });
}

// Cluster mode to utilize all CPU cores if enabled in configuration
if (env.USE_CLUSTER && cluster.isPrimary) {
    primaryBootstrap();
} else {
    bootstrap();
}