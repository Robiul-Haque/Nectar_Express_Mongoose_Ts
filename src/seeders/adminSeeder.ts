import User from "../modules/user/user.model";
import logger from '../utils/logger';
import { env } from '../config/env';

const seedAdmin = async (retries = 3, delayMs = 2000): Promise<void> => {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            if (!env.ADMIN_NAME || !env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) {
                logger.warn('⚠️ ADMIN credentials missing in env (ADMIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD).');
                return;
            }

            const existingAdmin = await User.findOne({ email: env.ADMIN_EMAIL, provider: "email" }).lean();

            if (existingAdmin) {
                logger.info('ℹ️ Admin already exists. Skipping seeding.');
                return;
            }

            await User.create({
                name: env.ADMIN_NAME,
                email: env.ADMIN_EMAIL,
                password: env.ADMIN_PASSWORD,
                provider: "email",
                role: "admin",
                isVerified: true,
            });

            logger.info('✅ Admin seeded successfully.');
            return;
        } catch (error: any) {
            if (error?.code === 11000) {
                logger.info('ℹ️ Admin already seeded by another worker process.');
                return;
            }
            const errorMsg = error instanceof Error ? error.message : String(error);
            if (attempt < retries) {
                logger.warn(`⚠️ Admin seeding attempt ${attempt}/${retries} failed (${errorMsg}). Retrying in ${delayMs / 1000}s...`);
                await new Promise((resolve) => setTimeout(resolve, delayMs));
            } else {
                logger.error('❌ Admin seeding failed: ' + errorMsg);
            }
        }
    }
};

export default seedAdmin;