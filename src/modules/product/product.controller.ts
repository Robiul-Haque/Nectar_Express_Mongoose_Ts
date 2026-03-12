import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import slugify from "slugify";
import httpStatus from "http-status";
import { Product } from "./product.model";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import mongoose from "mongoose";

export const createProduct = catchAsync(async (req: Request, res: Response) => {
    const payload: any = req.body;

    // Generate slug
    const slug = slugify(payload.name, { lower: true, strict: true });

    const exists = await Product.findOne({ slug }).lean();
    if (exists) return sendResponse(res, httpStatus.CONFLICT, "Product already exists");

    payload.slug = slug;

    // Image Upload
    if (req.file) {
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Products",
            publicId: `product-${Date.now()}`
        });

        payload.images = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const product = await Product.create(payload);

    return sendResponse(res, httpStatus.CREATED, "Product created successfully", null, product);
});

export const getAllProducts = catchAsync(async (_req, res) => {
    const products = await Product.find().populate("category", "name").populate("brand", "name").select("-nutrition").lean();

    return sendResponse(res, httpStatus.OK, "Products retrieved successfully", null, products);
});

// export const getSingleProduct = catchAsync(async (req, res) => {
//     const product = await Product.findById(req.params.id)
//         .populate("category", "name")
//         .populate("brand", "name")
//         .lean();

//     if (!product) {
//         return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
//     }

//     return sendResponse(res, httpStatus.OK, "Product retrieved successfully", null, product);
// });

export const updateProduct = catchAsync(async (req, res) => {
    const { id } = req.params;

    const product = await Product.findById(id);
    if (!product) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    const payload: any = { ...req.body };

    // slug update
    if (payload.name) payload.slug = slugify(payload.name, { lower: true, strict: true });

    if (req.file) {
        // delete old image
        if (product.image?.publicId) await deleteImage(product.image.publicId);

        // upload new image
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Products",
            publicId: `product-${Date.now()}`
        });

        payload.images = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const updatedProduct = await Product.findByIdAndUpdate(id, payload, { new: true, runValidators: true }).lean();

    return sendResponse(res, httpStatus.OK, "Product updated successfully", null, updatedProduct);
});

export const deleteProduct = catchAsync(async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid product id");

    const deleted = await Product.findByIdAndDelete(id).lean();
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    return sendResponse(res, httpStatus.OK, "Product deleted successfully");
});