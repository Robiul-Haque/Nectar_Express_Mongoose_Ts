import { Request, Response } from "express";
import mongoose from "mongoose";
import httpStatus from "http-status";
import { Review } from "./review.model";
import { Product } from "../product/product.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";

export const createReview = catchAsync(async (req: Request, res: Response) => {
    const payload = req.body;
    const userId = req.user?.sub;

    if (!mongoose.Types.ObjectId.isValid(payload.product)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid product id");

    const productExists = await Product.exists({ _id: payload.product });
    if (!productExists) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    const alreadyReviewed = await Review.findOne({ product: payload.product, user: userId }).lean();

    if (alreadyReviewed) return sendResponse(res, httpStatus.CONFLICT, "You already reviewed this product");

    const review = await Review.create({
        ...payload,
        user: userId
    });

    return sendResponse(res, httpStatus.CREATED, "Review created successfully", null, review);
});

export const getProductReviews = catchAsync(async (req: Request, res: Response) => {
    const { product } = req.query;
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;

    if (!mongoose.Types.ObjectId.isValid(product as string)) {
        return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid product id");
    }

    const skip = (page - 1) * limit;

    const reviews = await Review.find({ product })
        .populate("user", "name avatar")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean();

    const total = await Review.countDocuments({ product });

    return sendResponse(res, httpStatus.OK, "Reviews retrieved successfully", null, {
        meta: {
            page,
            limit,
            total
        },
        data: reviews
    });
});

export const getSingleReview = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid review id");

    const review = await Review.findById(id).populate("user", "name avatar").populate("product", "name slug").lean();
    if (!review) return sendResponse(res, httpStatus.NOT_FOUND, "Review not found");

    return sendResponse(res, httpStatus.OK, "Review retrieved successfully", null, review);
});

export const updateReview = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const userId = req.user?.sub;

    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid review id");

    const review = await Review.findById(id);
    if (!review) return sendResponse(res, httpStatus.NOT_FOUND, "Review not found");
    if (review.user.toString() !== userId) return sendResponse(res, httpStatus.FORBIDDEN, "You cannot update this review");

    const updatedReview = await Review.findByIdAndUpdate(id, req.body, { new: true, runValidators: true }).lean();

    return sendResponse(res, httpStatus.OK, "Review updated successfully", null, updatedReview);
});

export const deleteReview = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const userId = req.user?.sub;

    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid review id");

    const review = await Review.findById(id);
    if (!review) return sendResponse(res, httpStatus.NOT_FOUND, "Review not found");
    if (review.user.toString() !== userId) return sendResponse(res, httpStatus.FORBIDDEN, "You cannot delete this review");

    await Review.findByIdAndDelete(id);

    return sendResponse(res, httpStatus.OK, "Review deleted successfully");
});