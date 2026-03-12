import { Request, Response } from "express";
import mongoose from "mongoose";
import httpStatus from "http-status";
import { Review } from "./review.model";
import { Product } from "../product/product.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";

export const createReview = catchAsync(async (req: Request, res: Response) => {
    const { productId, rating, comment } = req.body;
    const userId = req.user?.sub;

    if (!mongoose.Types.ObjectId.isValid(productId)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid product id");

    // Check product exists
    const productExists = await Product.exists({ _id: productId });
    if (!productExists) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    // Prevent duplicate review
    const alreadyReviewed = await Review.exists({ product: productId, user: userId });

    if (alreadyReviewed) return sendResponse(res, httpStatus.CONFLICT, "You already reviewed this product");

    // Create review
    const review = await Review.create({ product: productId, user: userId, rating, comment });

    const stats = await Review.aggregate([
        {
            $match: { product: new mongoose.Types.ObjectId(productId) }
        },
        {
            $group: { _id: "$product", averageRating: { $avg: "$rating" }, totalReviews: { $sum: 1 } }
        }
    ]);

    if (stats.length > 0) await Product.findByIdAndUpdate(productId, { averageRating: Number(stats[0].averageRating.toFixed(1)), totalReviews: stats[0].totalReviews });

    return sendResponse(res, httpStatus.CREATED, "Review created successfully", null, review);
});

export const getProductReviews = catchAsync(async (req: Request, res: Response) => {
    const { productId: product } = req.query

    const page = Number(req.query.page) || 1
    const limit = Number(req.query.limit) || 10
    const skip = (page - 1) * limit

    if (!mongoose.Types.ObjectId.isValid(product as string)) {
        return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid product id")
    }

    const reviews = await Review.find({ product })
        .populate("user", "name avatar")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean()

    const total = await Review.countDocuments({ product })

    return sendResponse(res, httpStatus.OK, "Reviews retrieved successfully", { total, page, limit }, reviews)
})

// export const getSingleReview = catchAsync(async (req: Request, res: Response) => {
//     const { id } = req.params;

//     if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid review id");

//     const review = await Review.findById(id).populate("user", "name avatar").populate("product", "name slug").lean();
//     if (!review) return sendResponse(res, httpStatus.NOT_FOUND, "Review not found");

//     return sendResponse(res, httpStatus.OK, "Review retrieved successfully", null, review);
// });

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