import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "./user.model";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";

export const updateProfile = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;

    const updateData: any = {};

    // Text field validation by Zod
    if (req.body.name) updateData.name = req.body.name;

    // File upload handled by Multer
    if (req.file) {
        const folderPath = "Nectar/Users";
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: folderPath,
            publicId: `user-${userId}-${Date.now()}`,
        });

        updateData.avatar = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };

        // Delete old avatar
        const existingUser = await User.findById(userId).select("avatar").lean<{ avatar?: { publicId?: string } }>();

        if (existingUser?.avatar?.publicId) {
            try {
                await deleteImage(existingUser.avatar.publicId);
            } catch (err) {
                console.error("[Cloudinary Delete Error]", err);
            }
        }
    }

    // Check if at least one field provided
    if (!Object.keys(updateData).length) return sendResponse(res, status.BAD_REQUEST, "At least one field (name or profile image) must be provided");

    const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: updateData },
        {
            new: true,
            runValidators: true,
            projection: {
                name: 1,
                email: 1,
                avatar: 1,
                role: 1,
                isVerified: 1,
            },
        }
    ).lean();

    return sendResponse(res, status.OK, "Profile updated successfully", updatedUser);
});

export const getProfile = catchAsync(async (req: Request, res: Response) => {
    if (!req.user) return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");

    const userId = req.user.sub;

    const user = await User.findById(userId).select("-_id name email avatar").lean();
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    return sendResponse(res, status.OK, "Profile retrieved successfully", user);
});