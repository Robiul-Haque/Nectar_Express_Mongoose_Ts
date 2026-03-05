import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import { Category } from "./category.model";
import httpStatus from "http-status";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import mongoose from "mongoose";

export const createCategory = catchAsync(async (req: Request, res: Response) => {
    const { name, description, featured: isFeatured, order: sortOrder } = req.body;

    const exists = await Category.exists({ name: { $regex: `^${name}$`, $options: "i" }, });
    if (exists) return sendResponse(res, httpStatus.CONFLICT, "Category already exists");

    const payload: any = { name, description, isFeatured, sortOrder };

    if (req.file) {
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Categories",
            publicId: `category-${Date.now()}`,
        });

        payload.icon = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };
    }

    const category = await Category.create(payload);

    return sendResponse(res, httpStatus.CREATED, "Category created successfully", null, category);
});

export const getAllCategories = catchAsync(async (req: Request, res: Response) => {
    const { search, page = 1, limit = 10, active: isActive } = req.query;

    const filter: any = {};

    if (search) filter.$text = { $search: search as string };

    if (isActive !== undefined) filter.isActive = isActive === "true";

    const skip = (Number(page) - 1) * Number(limit);

    const [data, total] = await Promise.all([
        Category.find(filter).sort({ sortOrder: 1, createdAt: -1 }).skip(skip).limit(Number(limit)).lean(),
        Category.countDocuments(filter)
    ]);

    return sendResponse(res, httpStatus.OK, "Categories fetched", { total, page: Number(page), limit: Number(limit) }, data);
});

// export const getSingleCategory = catchAsync(async (req: Request, res: Response) => {
//     const category = await Category.findById(req.params.id).lean();
//     if (!category) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

//     return sendResponse(res, httpStatus.OK, "Category fetched", category);
// });

export const updateCategory = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid category id");

    const category = await Category.findById(id);
    if (!category) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

    const updateData: any = { ...req.body };

    if (req.file) {
        if (category.icon?.publicId) await deleteImage(category.icon.publicId);

        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Categories",
            publicId: `category-${Date.now()}`
        });

        updateData.icon = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const updated = await Category.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).lean();

    return sendResponse(res, httpStatus.OK, "Category updated successfully", null, updated);
});

export const deleteCategory = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id as string)) return sendResponse(res, httpStatus.BAD_REQUEST, "Invalid category id");

    const deleted = await Category.findByIdAndDelete(req.params.id);
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

    if (deleted.icon?.publicId) await deleteImage(deleted.icon.publicId);

    return sendResponse(res, httpStatus.OK, "Category deleted successfully", null);
});