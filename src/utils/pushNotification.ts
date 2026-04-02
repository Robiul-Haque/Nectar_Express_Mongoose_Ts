import { firebaseAdmin } from "../config/firebaseAdmin.config";
import User from "../modules/user/user.model";
import mongoose from "mongoose";

export type TPushPayload = {
    title: string;
    body: string;
    image?: string;
};

type TSendOptions = {
    userIds?: string[];
};

export const sendPushNotification = async (payload: TPushPayload, options?: TSendOptions) => {
    const { title, body, image } = payload;
    const { userIds } = options || {};

    const query: any = {
        notificationEnabled: true,
        device: { $exists: true, $ne: [] }
    };

    // Safe ObjectId handling
    if (userIds?.length) {
        const validIds = userIds.filter(id => mongoose.Types.ObjectId.isValid(id));
        if (!validIds.length) return { successCount: 0, failureCount: 0 };

        query._id = { $in: validIds.map(id => new mongoose.Types.ObjectId(id)) };
    }

    // lean for performance
    const users = await User.find(query).select("+device").lean();
    if (!users.length) return { successCount: 0, failureCount: 0 };

    const tokens: string[] = [];

    for (const user of users) {
        user.device?.forEach((d: any) => {
            if (d.token) tokens.push(d.token);
        });
    }

    if (!tokens.length) return { successCount: 0, failureCount: 0 };

    const uniqueTokens = [...new Set(tokens)];

    // chunk (FCM limit = 500)
    const chunkSize = 500;
    let successCount = 0;
    let failureCount = 0;
    const failedTokens: string[] = [];

    for (let i = 0; i < uniqueTokens.length; i += chunkSize) {
        const chunk = uniqueTokens.slice(i, i + chunkSize);

        const message = {
            notification: { title, body, ...(image ? { image } : {}) },
            tokens: chunk
        };

        const response = await firebaseAdmin.messaging().sendEachForMulticast(message);

        successCount += response.successCount;
        failureCount += response.failureCount;

        response.responses.forEach((res, index) => {
            if (!res.success) failedTokens.push(chunk[index]);
        });
    }

    // optimized cleanup
    if (failedTokens.length) await User.updateMany({ "device.token": { $in: failedTokens } }, { $pull: { device: { token: { $in: failedTokens } } } });

    return { successCount, failureCount };
};