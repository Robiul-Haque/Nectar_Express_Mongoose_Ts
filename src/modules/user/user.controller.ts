import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "./user.model";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";

export const updateLocation = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { location } = req.body;

    const user = await User.findById(userId).select("isActive");
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

    // Update location in DB
    const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $set: { location } },
        { new: true, runValidators: true, projection: { location: 1, name: 1, email: 1 } }
    ).lean();

    if (!updatedUser) return sendResponse(res, 404, "User not found");

    return sendResponse(res, 200, "Location updated successfully", null, updatedUser);
});

export const getLocation = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;

    const user = await User.findById(userId).select("-_id location name email isActive").lean();
    if (!user) return sendResponse(res, 404, "User not found");
    if (!user.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive. Please contact support");

    return sendResponse(res, 200, "User location retrieved successfully", null, user);
});

export const updateProfile = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;

    const updateData: any = {};

    const user = await User.findById(userId);
    if (!user?.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive");

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

    return sendResponse(res, status.OK, "Profile updated successfully", null, updatedUser);
});

export const getProfile = catchAsync(async (req: Request, res: Response) => {
    if (!req.user) return sendResponse(res, status.UNAUTHORIZED, "User not authenticated");
    const userId = req.user.sub;

    const user = await User.findById(userId).select("-_id name email avatar").lean();
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");
    if (!user?.isActive) return sendResponse(res, status.UNAUTHORIZED, "Account is inactive");

    return sendResponse(res, status.OK, "Profile retrieved successfully", null, user);
});

export const getAllUsers = catchAsync(async (req: Request, res: Response) => {
    const { search, isActive, page = 1, limit = 10 } = req.query;

    // Filter to exclude admins
    const filter: any = { role: { $ne: "admin" } };

    // Search by name or email
    if (search) {
        filter.$or = [
            { name: { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } }
        ];
    }

    // Filter by active status if provided
    if (isActive !== undefined) {
        filter.isActive = isActive === "true";
    }

    const skip = (Number(page) - 1) * Number(limit);
    const limitNum = Number(limit);

    // Optimized parallel execution for data and total count
    const [users, total] = await Promise.all([
        User.find(filter)
            .select("name email avatar role isActive isVerified location notificationEnabled provider createdAt")
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limitNum)
            .lean(),
        User.countDocuments(filter)
    ]);

    const pagination = {
        total,
        page: Number(page),
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum)
    };

    return sendResponse(res, status.OK, "Users retrieved successfully", pagination, users);
});

/**
 * @desc Toggle user active status (Block/Unblock)
 * @route PATCH /api/users/toggle-status/:id
 * @access Private (Admin)
 */
export const toggleUserStatus = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { isActive } = req.body;

    const user = await User.findByIdAndUpdate(
        id,
        { $set: { isActive } },
        { new: true, runValidators: true, projection: "name email isActive" }
    ).lean();

    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");

    const message = isActive ? "User account unblocked successfully" : "User account blocked successfully";
    return sendResponse(res, status.OK, message, null, user);
});