import mongoose from 'mongoose';
import { env } from './config/env';
import logger from './utils/logger';
import seedAdmin from './seeders/adminSeeder';
import { verifySMTP } from './utils/sendOtpEmail';
import { server } from './app';

async function bootstrap() {
    // Start server instantly
    const newServer = server.listen(env.PORT, () => logger.info(`🚀 Server running on port ${env.PORT}`));

    // DB connect (background)
    mongoose
        .connect(env.DB_URL)
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
        logger.warn('SIGTERM received. Shutting down...');
        await mongoose.disconnect();
        newServer.close();
        process.exit(0);
    });
}

bootstrap();