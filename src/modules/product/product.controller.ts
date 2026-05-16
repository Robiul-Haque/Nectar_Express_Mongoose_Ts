import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import slugify from "slugify";
import httpStatus from "http-status";
import Product from "./product.model";
import { sendPushNotification, TPushPayload } from "../../utils/pushNotification";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import logger from "../../utils/logger";

export const createProduct = catchAsync(async (req: Request, res: Response) => {
    const payload: any = req.body;

    // Generate slug
    const slug = slugify(payload.name, { lower: true, strict: true });

    const exists = await Product.findOne({ slug }).lean();
    if (exists) return sendResponse(res, httpStatus.CONFLICT, "Product already exists");

    payload.slug = slug;

    // Upload image (if exists)
    if (req.file) {
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Products",
            publicId: `product-${Date.now()}`
        });

        payload.image = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const product = await Product.create(payload);

    const pushPayload: TPushPayload = {
        title: "🆕 New Product Available!",
        body: `${product.name} is now available. Grab yours today!`,
        ...(product.image?.url && { image: product.image.url })
    };

    // Send push (non-blocking)
    sendPushNotification(pushPayload).catch(err => console.error("Push Notification Error:", err?.message || err));

    return sendResponse(res, httpStatus.CREATED, "Product created successfully", { notification: "Push notification triggered" }, product);
});

export const getAllProducts = catchAsync(async (_req: Request, res: Response) => {
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

export const updateProduct = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const product = await Product.findById(id);
    if (!product) {
        logger.warn(`Product not found: ${id}`);
        return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
    }

    const payload: any = {};

    if (req.body.name) {
        payload.name = req.body.name;
        payload.slug = slugify(req.body.name, { lower: true, strict: true });
    }

    if (req.body.description) payload.description = req.body.description;
    if (req.body.price !== undefined) payload.price = Number(req.body.price);
    if (req.body.stock !== undefined) payload.stock = Number(req.body.stock);

    // Normalize boolean again safety layer
    const toBoolean = (val: any) => {
        if (val === true || val === false) return val;
        if (val === "true") return true;
        if (val === "false") return false;
        return undefined;
    };

    if (req.body.isFeatured !== undefined) payload.isFeatured = toBoolean(req.body.isFeatured);
    if (req.body.isActive !== undefined) payload.isActive = toBoolean(req.body.isActive);
    if (req.file) {
        if (product.image?.publicId) await deleteImage(product.image.publicId);

        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Products",
            publicId: `product-${Date.now()}`
        });

        payload.image = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const updatedProduct = await Product.findByIdAndUpdate(id, { $set: payload }, { new: true, runValidators: true }).lean();

    return sendResponse(res, httpStatus.OK, "Product updated successfully", null, updatedProduct);
});

export const deleteProduct = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const deleted = await Product.findByIdAndDelete(id).lean();
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    return sendResponse(res, httpStatus.OK, "Product deleted successfully");
});