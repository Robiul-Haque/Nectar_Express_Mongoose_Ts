import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import Brand from "./brand.model";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import status from "http-status";

export const createBrand = catchAsync(async (req: Request, res: Response) => {
    const { name } = req.body;

    const existing = await Brand.findOne({ name: { $regex: `^${name}$`, $options: "i" } }).lean();
    if (existing) return sendResponse(res, status.CONFLICT, "Brand already exists");

    const brandData: any = { name };

    // Logo Upload
    if (req.file) {
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Brands",
            publicId: `brand-${Date.now()}`,
        });

        brandData.logo = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };
    }

    const brand = await Brand.create(brandData);

    return sendResponse(res, status.CREATED, "Brand created successfully", null, brand);
});

export const getAppBrands = catchAsync(async (_req: Request, res: Response) => {
    const brands = await Brand.find({ isActive: true }).select("name -_id").sort({ name: 1 }).lean();

    return sendResponse(res, status.OK, "Brands fetched successfully", null, brands);
});

export const getAllBrands = catchAsync(async (req: Request, res: Response) => {
    const { page = 1, limit = 10, search, active: isActive } = req.query as any;

    const filter: any = {};
    if (search) filter.$text = { $search: search };
    if (isActive !== undefined) filter.isActive = isActive === "true";

    const skip = (Number(page) - 1) * Number(limit);

    const [brands, total] = await Promise.all([
        Brand.find(filter).select("name logo isActive createdAt").sort({ createdAt: -1 }).skip(skip).limit(Number(limit)).lean(),
        Brand.countDocuments(filter),
    ]);

    return sendResponse(res, 200, "Brands retrieved successfully", { page: Number(page), limit: Number(limit), total, totalPages: Math.ceil(total / Number(limit)) }, brands);
})

export const getSingleBrand = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const brand = await Brand.findById(id).select("name logo isActive createdAt updatedAt").lean();
    if (!brand) return sendResponse(res, status.NOT_FOUND, "Brand not found");

    return sendResponse(res, status.OK, "Brand retrieved successfully", null, brand);
});

export const updateBrand = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const brand = await Brand.findById(id);
    if (!brand) return sendResponse(res, status.NOT_FOUND, "Brand not found");

    const { name, isActive: isActiveStr } = req.body;

    const updateData: Record<string, any> = {};

    if (name) updateData.name = name;

    if (isActiveStr !== undefined) {
        if (typeof isActiveStr === "string") {
            updateData.isActive = isActiveStr.toLowerCase() === "true";
        } else {
            updateData.isActive = Boolean(isActiveStr);
        }
    }

    if (req.file) {
        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Brands",
            publicId: `brand-${id}-${Date.now()}`,
        });

        updateData.logo = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };

        if (brand.logo?.publicId) {
            try {
                await deleteImage(brand.logo.publicId.toString());
            } catch (err) {
                console.error("[Cloudinary Delete Error]", err);
            }
        }
    }

    if (!Object.keys(updateData).length) return sendResponse(res, status.BAD_REQUEST, "No update data provided");

    const updatedBrand = await Brand.findByIdAndUpdate(id, { $set: updateData }, { new: true, runValidators: true }).lean();

    return sendResponse(res, status.OK, "Brand updated successfully", null, updatedBrand);
});

export const deleteBrand = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const brand = await Brand.findById(id).lean();
    if (!brand) return sendResponse(res, status.NOT_FOUND, "Brand not found");

    if (brand.logo?.publicId) {
        try {
            await deleteImage(brand.logo.publicId.toString());
        } catch (err) {
            console.error("[Cloudinary Delete Error]", err);
        }
    }

    await Brand.deleteOne({ _id: id });
    
    return sendResponse(res, status.OK, "Brand deleted permanently", null);
});