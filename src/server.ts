import mongoose from 'mongoose';
import cluster from 'cluster';
import os from 'os';
import dns from 'dns';
import { env } from './config/env';
import logger from './utils/logger';
import seedAdmin from './seeders/adminSeeder';
import { verifySMTP } from './utils/sendOtpEmail';
import { server } from './app';

// Set default DNS resolution order to IPv4 first to prevent EAI_AGAIN DNS timeouts in Docker
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}

async function bootstrap() {
    // Start server instantly
    const newServer = server.listen(env.PORT, '0.0.0.0', () => console.log(`🚀 Worker ${process.pid} running on port ${env.PORT}`));

    // DB connect (background)
    const dbUrl = env.DB_URL;

    if (!dbUrl) {
        logger.error('❌ DB_URL is not defined');
        process.exit(1);
    }

    mongoose
        .connect(dbUrl)
        .then(async () => {
            if (!cluster.isWorker || cluster.worker?.id === 1) {
                logger.info('✅ DB connected');
                await seedAdmin();
            }
        })
        .catch((err) => {
            logger.error('❌ DB connection failed', err);
            process.exit(1);
        });

    // mongoose.set("debug", true);

    // SMTP verify (background — NON BLOCKING, run only on single process or worker 1)
    if (env.NODE_ENV !== 'production' && (!cluster.isWorker || cluster.worker?.id === 1)) {
        verifySMTP();
    }

    // Global Process Error Handlers
    process.on('unhandledRejection', (reason: unknown) => {
        logger.error(`❌ Unhandled Rejection: ${reason instanceof Error ? reason.message : String(reason)}`);
    });

    process.on('uncaughtException', (error: Error) => {
        logger.error(`❌ Uncaught Exception: ${error.message}`);
    });

    // Graceful shutdown
    const handleShutdown = async (signal: string) => {
        logger.warn(`Worker ${process.pid} ${signal} received. Shutting down...`);
        try {
            await mongoose.disconnect();
            newServer.close(() => {
                process.exit(0);
            });
        } catch {
            process.exit(0);
        }
    };

    process.on('SIGTERM', () => handleShutdown('SIGTERM'));
    process.on('SIGINT', () => handleShutdown('SIGINT'));
}

// Cluster mode to utilize all CPU cores if enabled in configuration
if (env.USE_CLUSTER && cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`⚡ Primary cluster process ${process.pid} is running. Spawning ${numCPUs} workers...`);

    // Fork workers
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker) => {
        if (!worker.exitedAfterDisconnect) {
            console.warn(`⚠️ Worker process ${worker.process.pid} died. Spawning a replacement...`);
            cluster.fork();
        }
    });
} else {
    bootstrap();
}