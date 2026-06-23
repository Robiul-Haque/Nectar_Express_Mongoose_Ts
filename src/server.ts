import mongoose from 'mongoose';
import cluster from 'cluster';
import os from 'os';
import { env } from './config/env';
import logger from './utils/logger';
import seedAdmin from './seeders/adminSeeder';
import { verifySMTP } from './utils/sendOtpEmail';
import { server } from './app';

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
            logger.info('✅ DB connected');
            await seedAdmin();
        })
        .catch((err) => {
            logger.error('❌ DB connection failed', err);
            process.exit(1);
        });

    // mongoose.set("debug", true);

    // SMTP verify (background — NON BLOCKING)
    if (env.NODE_ENV !== 'production') verifySMTP();

    // Graceful shutdown
    process.on('SIGTERM', async () => {
        logger.warn(`Worker ${process.pid} SIGTERM received. Shutting down...`);
        await mongoose.disconnect();
        newServer.close();
        process.exit(0);
    });
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
        console.warn(`⚠️ Worker process ${worker.process.pid} died. Spawning a replacement...`);
        cluster.fork();
    });
} else {
    bootstrap();
}