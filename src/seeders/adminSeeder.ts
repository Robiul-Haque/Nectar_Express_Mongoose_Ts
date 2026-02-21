import bcrypt from "bcrypt";
import mongoose from 'mongoose';
import User from "../modules/user/user.model";
import logger from '../utils/logger';
import { env } from '../config/env';

export const seedAdmin = async () => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const existingAdmin = await User.findOne({
            email: env.ADMIN_EMAIL,
        }).lean();

        if (existingAdmin) {
            logger.info('ℹ️ Admin already exists. Skipping seeding.');
            await session.abortTransaction();
            session.endSession();
            return;
        }

        const hashedPassword = await bcrypt.hash(env.ADMIN_PASSWORD, 12);

        await User.create(
            [
                {
                    name: env.ADMIN_NAME || 'Admin',
                    email: env.ADMIN_EMAIL,
                    password: hashedPassword,
                    role: 'admin',
                    isVerified: true,
                },
            ],
            { session }
        );

        await session.commitTransaction();
        session.endSession();

        logger.info('✅ Admin seeded successfully.');
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        logger.error('❌ Admin seeding failed: ' + (error instanceof Error ? error.message : String(error)));
        process.exit(1);
    }
};