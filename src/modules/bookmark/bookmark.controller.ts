import { Request, Response } from "express";
import httpStatus from "http-status";
import Bookmark from "./bookmark.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import { getCache, setCache, deletePattern } from "../../utils/redis";

export const toggleBookmark = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub as string;
    const { productId: product } = req.body;

    const existingBookmark = await Bookmark.findOne({ user: userId, product });

    if (existingBookmark) {
        // If bookmark exists, remove it (toggle off)
        await Bookmark.deleteOne({ _id: existingBookmark._id });

        // Invalidate cached bookmark listings for this user
        await deletePattern(`cache:bookmark:${userId}:*`);

        return sendResponse(res, httpStatus.OK, "Bookmark removed successfully", null, { isBookmarked: false });
    } else {
        // If bookmark doesn't exist, add it (toggle on)
        const bookmark = await Bookmark.create({ user: userId, product });

        // Invalidate cached bookmark listings for this user
        await deletePattern(`cache:bookmark:${userId}:*`);

        return sendResponse(res, httpStatus.CREATED, "Bookmark added successfully", null, { isBookmarked: true, bookmark });
    }
});

export const getBookmarks = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub as string;
    if (!userId) return sendResponse(res, httpStatus.UNAUTHORIZED, "User not authenticated");

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const cacheKey = `cache:bookmark:${userId}:page:${page}:limit:${limit}`;

    // Attempt to retrieve cached bookmarks
    const cachedData = await getCache(cacheKey);
    if (cachedData) {
        try {
            const { bookmarks, total } = JSON.parse(cachedData);
            return sendResponse(res, httpStatus.OK, "Bookmarks retrieved successfully", { total, page, limit }, bookmarks);
        } catch (err) {
            // Ignore parse errors and fallback
        }
    }

    const [bookmarks, total] = await Promise.all([
        Bookmark.find({ user: userId })
            .select("-updatedAt")
            .populate({ path: "product" })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean(),

        Bookmark.countDocuments({ user: userId })
    ]);

    // Cache the list of bookmarks for 5 minutes (300 seconds)
    await setCache(cacheKey, JSON.stringify({ bookmarks, total }), 300);

    return sendResponse(res, httpStatus.OK, "Bookmarks retrieved successfully", { total, page, limit }, bookmarks);
});