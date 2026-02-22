import User from "../modules/user/user.model";
import logger from '../utils/logger';
import { env } from '../config/env';

export const seedAdmin = async () => {
    try {
        if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) {
            logger.warn('⚠️ ADMIN credentials missing in env.');
            return;
        }

        const existingAdmin = await User.findOne({email: env.ADMIN_EMAIL,provider: "email"}).lean();

        if (existingAdmin) {
            logger.info('ℹ️ Admin already exists. Skipping seeding.');
            return;
        }

        await User.create({
            name: env.ADMIN_NAME || 'Admin',
            email: env.ADMIN_EMAIL,
            password: env.ADMIN_PASSWORD,
            provider: "email",
            role: "admin",
            isVerified: true,
        });

        logger.info('✅ Admin seeded successfully.');
    } catch (error) {
        logger.error(
            '❌ Admin seeding failed: ' +
            (error instanceof Error ? error.message : String(error))
        );
    }
};