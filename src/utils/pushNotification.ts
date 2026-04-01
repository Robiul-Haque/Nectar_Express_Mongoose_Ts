import { firebaseAdmin } from "../config/firebaseAdmin.config";
import User from "../modules/user/user.model";

type TPushPayload = {
    title: string;
    body: string;
    image?: string;
};

export const sendPushNotificationToAllUsers = async (payload: TPushPayload) => {
    const { title, body, image } = payload;

    // Get users who enabled notifications and have devices
    const users = await User.find({ notificationEnabled: true, device: { $exists: true, $ne: [] } }).select("+device");

    const tokens: string[] = [];
    users.forEach(user => {
        user.device?.forEach(d => {
            if (d.token) tokens.push(d.token);
        });
    });

    if (!tokens.length) return { successCount: 0, failureCount: 0 };

    // Remove duplicate tokens
    const uniqueTokens = [...new Set(tokens)];

    const message = {
        notification: { title, body, image },
        tokens: uniqueTokens
    };

    const response = await firebaseAdmin.messaging().sendEachForMulticast(message);

    // Cleanup invalid tokens
    if (response.failureCount > 0) {
        const failedTokens: string[] = [];

        response.responses.forEach((res, index) => {
            if (!res.success) failedTokens.push(uniqueTokens[index]);
        });

        if (failedTokens.length) {
            await User.updateMany({ "device.token": { $in: failedTokens } }, { $pull: { device: { token: { $in: failedTokens } } } });
        }
    }

    return {
        successCount: response.successCount,
        failureCount: response.failureCount
    };
};