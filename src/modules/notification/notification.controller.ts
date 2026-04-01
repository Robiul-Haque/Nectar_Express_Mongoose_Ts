import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import User from "../user/user.model";
import status from "http-status";
import sendResponse from "../../utils/sendResponse";

export const registerDevice = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { token, platform, deviceId } = req.body;

    const user = await User.findById(userId).select("+device");
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");
    if (!user.device) user.device = [];

    const index = user.device.findIndex(d => d.token === token);

    let message = "Device token registered";

    if (index !== -1) {
        user.device[index] = {
            token,
            platform,
            deviceId: deviceId || null,
            lastActive: new Date()
        };
        message = "Device token updated";
    } else {
        user.device.push({
            token,
            platform,
            deviceId: deviceId || null,
            lastActive: new Date()
        });
    }

    user.markModified("device");

    await user.save();

    return sendResponse(res, status.OK, message, null, { token, platform, deviceId: deviceId || null });
});

export const toggleNotification = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { enabled } = req.body;

    const user = await User.findByIdAndUpdate(userId, { notificationEnabled: enabled }, { new: true, select: "notificationEnabled" });
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    return sendResponse(res, status.OK, `Notifications ${enabled ? "enabled" : "disabled"} successfully`, null, { notificationEnabled: user.notificationEnabled });
});