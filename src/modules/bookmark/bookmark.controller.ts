import { Request, Response } from "express";
import httpStatus from "http-status";
import Bookmark from "./bookmark.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";

export const createBookmark = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub as string;
    const { product } = req.body;

    // duplicate bookmark prevent
    const isExist = await Bookmark.exists({ user: userId, product });
    if (isExist) return sendResponse(res, httpStatus.CONFLICT, "Product already bookmarked");

    const bookmark = await Bookmark.create({ user: userId, product });

    return sendResponse(res, httpStatus.CREATED, "Bookmark added successfully", null, bookmark);
});

export const deleteBookmark = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub as string;
    const { productId } = req.params;

    const deleted = await Bookmark.findOneAndDelete({ user: userId, product: productId });
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Bookmark not found");

    return sendResponse(res, httpStatus.OK, "Bookmark removed successfully");
});

export const getBookmarks = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user?.sub as string;

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const [bookmarks, total] = await Promise.all([
        Bookmark.find({ user: userId })
            .populate({ path: "product", select: "name price images slug" })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .lean(),

        Bookmark.countDocuments({ user: userId })
    ]);

    return sendResponse(res, httpStatus.OK, "Bookmarks retrieved successfully", { total, page, limit }, bookmarks);
});