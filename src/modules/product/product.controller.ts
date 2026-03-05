import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import slugify from "slugify";
import httpStatus from "http-status";
import { Product } from "./product.model";
import sendResponse from "../../utils/sendResponse";
import { uploadImageStream } from "../../utils/cloudinary";

export const createProduct = catchAsync(async (req: Request, res: Response) => {
    const payload: any = req.body;

    // Generate slug
    const slug = slugify(payload.name, { lower: true, strict: true });

    const exists = await Product.findOne({ slug }).lean();
    if (exists) return sendResponse(res, httpStatus.CONFLICT, "Product already exists");

    payload.slug = slug;

    // Image Upload
    if (req.files && Array.isArray(req.files)) {
        payload.images = [];

        for (const file of req.files) {
            const uploadResult = await uploadImageStream(file.buffer, {
                folder: "Nectar/Products",
                publicId: `product-${Date.now()}`,
            });

            payload.images.push({
                url: uploadResult.secure_url,
                publicId: uploadResult.public_id,
            });
        }
    }

    const product = await Product.create(payload);

    return sendResponse(res, httpStatus.CREATED, "Product created successfully", null, product);
});

export const getAllProducts = catchAsync(async (_req, res) => {
    const products = await Product.find()
        .populate("category", "name")
        .populate("brand", "name")
        .select("-nutrition") // optional optimization
        .lean();

    return sendResponse(res, httpStatus.OK, "Products fetched", null, products);
});

export const getSingleProduct = catchAsync(async (req, res) => {
    const product = await Product.findById(req.params.id)
        .populate("category", "name")
        .populate("brand", "name")
        .lean();

    if (!product) {
        return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
    }

    return sendResponse(res, httpStatus.OK, "Product fetched", null, product);
});

export const updateProduct = catchAsync(async (req, res) => {
    const payload: any = req.body;

    if (payload.name) {
        payload.slug = slugify(payload.name, { lower: true, strict: true });
    }

    const updated = await Product.findByIdAndUpdate(
        req.params.id,
        payload,
        {
            new: true,
            runValidators: true,
        }
    ).lean();

    if (!updated) {
        return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
    }

    return sendResponse(res, httpStatus.OK, "Product updated", null, updated);
});

export const deleteProduct = catchAsync(async (req, res) => {
    const deleted = await Product.findByIdAndDelete(req.params.id).lean();

    if (!deleted) {
        return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
    }

    return sendResponse(res, httpStatus.OK, "Product deleted successfully");
});