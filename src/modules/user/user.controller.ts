import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "./user.model";
import { updateProfileSchema } from "../auth/auth.validation";

export const updateProfile = catchAsync(async (req: Request, res: Response) => {
    // Validate request body
    const parsed = updateProfileSchema.safeParse(req.body);

    if (!parsed.success) return sendResponse(res, status.BAD_REQUEST, "Invalid input", parsed.error.format());

    if (!req.user) return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");

    const userId = req.user.sub; // assuming JWT middleware sets this

    const { name, avatar } = parsed.data;

    // Ensure at least one field is provided
    if (name === undefined && avatar === undefined) {
        return sendResponse(res, status.BAD_REQUEST, "At least one field (name or avatar) must be provided");
    }

    // Prepare dynamic update object (only provided fields)
    const updateData: Record<string, unknown> = {};

    if (name !== undefined) updateData.name = name;
    if (avatar !== undefined) updateData.avatar = avatar;

    // Atomic update
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
                isVerified: 1
            }
        }
    ).lean();

    if (!updatedUser) return sendResponse(res, status.NOT_FOUND, "User not found");

    return sendResponse(res, status.OK, "Profile updated successfully", updatedUser);
});

export const getProfile = catchAsync(async (req: Request, res: Response) => {
    if (!req.user) return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");

    const userId = req.user.sub;

    // Minimal, safe projection (never expose sensitive fields)
    const user = await User.findById(userId).select("name email avatar").lean();
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    return sendResponse(res,status.OK,"Profile retrieved successfully",user);
});