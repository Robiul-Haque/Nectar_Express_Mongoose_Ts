import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "./user.model";
import { updateProfileSchema } from "../auth/auth.validation";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";

export const updateProfile = catchAsync(async (req: Request, res: Response) => {
    // Validate request body using Zod
    const parsed = updateProfileSchema.safeParse(req.body);
    if (!parsed.success) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());
    }

    // Ensure user is authenticated (set by JWT middleware)
    if (!req.user) {
        return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");
    }

    const userId = req.user.sub;
    const { name } = parsed.data;

    // Ensure at least one field is provided
    if (!name && !req.file) {
        return sendResponse(res, status.BAD_REQUEST, "At least one field (name or profile image) must be provided");
    }

    // Fetch existing user (minimal projection for optimization)
    const existingUser = await User.findById(userId)
        .select("avatar")
        .lean<{ avatar?: { url: string; publicId: string } }>();
    if (!existingUser) {
        return sendResponse(res, status.NOT_FOUND, "User not found");
    }

    const updateData: Record<string, any> = {};

    // Handle profile image upload if provided
    if (req.file) {
        const folderPath = "nectar/users/profile";

        // a) Upload new image to Cloudinary
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: folderPath,
            publicId: `user-${userId}-${Date.now()}`,
        });

        updateData.avatar = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };

        // b) Delete old image AFTER successful upload
        if (existingUser.avatar?.publicId) {
            try {
                await deleteImage(existingUser.avatar.publicId);
            } catch (err) {
                // Log error but do NOT block profile update
                console.error("[Cloudinary Delete Error]", err);
            }
        }
    }

    // Update name if provided
    if (name) updateData.name = name;

    // Atomic update with validation and projection
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

    // Return response
    return sendResponse(res, status.OK, "Profile updated successfully", updatedUser);
});

export const getProfile = catchAsync(async (req: Request, res: Response) => {
    if (!req.user) return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");

    const userId = req.user.sub;

    // Minimal, safe projection (never expose sensitive fields)
    const user = await User.findById(userId).select("name email avatar").lean();
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    return sendResponse(res, status.OK, "Profile retrieved successfully", user);
});