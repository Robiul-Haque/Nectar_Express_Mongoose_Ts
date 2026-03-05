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