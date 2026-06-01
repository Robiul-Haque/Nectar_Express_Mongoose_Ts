import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import Category from "./category.model";
import Product from "../product/product.model";
import httpStatus from "http-status";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";

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
    if (search) {
        filter.$or = [
            { name: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } }
        ];
    }
    if (isActive !== undefined) filter.isActive = isActive === "true";

    const skip = (Number(page) - 1) * Number(limit);
    const limitNum = Number(limit);

    const pipeline: any[] = [
        { $match: filter },
        {
            $lookup: {
                from: "products",
                let: { catId: "$_id" },
                pipeline: [
                    { $match: { $expr: { $eq: ["$category", "$$catId"] } } },
                    { $count: "count" }
                ],
                as: "productCountInfo"
            }
        },
        {
            $addFields: {
                productCount: { $ifNull: [{ $arrayElemAt: ["$productCountInfo.count", 0] }, 0] }
            }
        },
        { $project: { productCountInfo: 0 } },
        { $sort: { sortOrder: 1, createdAt: -1 } },
        {
            $facet: {
                metadata: [{ $count: "total" }],
                data: [{ $skip: skip }, { $limit: limitNum }]
            }
        }
    ];

    const result = await Category.aggregate(pipeline);
    const data = result[0].data;
    const total = result[0].metadata[0]?.total || 0;

    const pagination = {
        total,
        page: Number(page),
        limit: limitNum
    };

    return sendResponse(res, httpStatus.OK, "Categories retrieved successfully", pagination, data);
});

export const getCategoryStats = catchAsync(async (req: Request, res: Response) => {
    const [totalCategories, activeProducts, stockInfo] = await Promise.all([
        Category.countDocuments(),
        Product.countDocuments({ isActive: true }),
        Product.aggregate([
            {
                $group: {
                    _id: null,
                    totalStock: { $sum: "$stock" },
                    inStockItems: {
                        $sum: { $cond: [{ $gt: ["$stock", 0] }, 1, 0] }
                    },
                    totalItems: { $sum: 1 }
                }
            }
        ])
    ]);

    const stats = {
        totalCategories,
        activeItems: activeProducts,
        stockHealth: stockInfo.length > 0 && stockInfo[0].totalItems > 0
            ? Math.round((stockInfo[0].inStockItems / stockInfo[0].totalItems) * 100) 
            : 0
    };

    return sendResponse(res, httpStatus.OK, "Category stats retrieved successfully", null, stats);
});

// export const getSingleCategory = catchAsync(async (req: Request, res: Response) => {
//     const category = await Category.findById(req.params.id).lean();
//     if (!category) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

//     return sendResponse(res, httpStatus.OK, "Category retrieved successfully", category);
// });

export const updateCategory = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const category = await Category.findById(id);
    if (!category) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

    const payload: any = { ...req.body };

    if (req.file) {
        if (category.icon?.publicId) await deleteImage(category.icon.publicId);

        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: "Nectar/Categories",
            publicId: `category-${Date.now()}`
        });

        payload.icon = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id
        };
    }

    const updatedCategory = await Category.findByIdAndUpdate(id, payload, { new: true, runValidators: true }).lean();
    if (!updatedCategory) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

    return sendResponse(res, httpStatus.OK, "Category updated successfully", null, updatedCategory);

});

export const deleteCategory = catchAsync(async (req: Request, res: Response) => {
    const deleted = await Category.findByIdAndDelete(req.params.id);
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Category not found");

    if (deleted.icon?.publicId) await deleteImage(deleted.icon.publicId);

    return sendResponse(res, httpStatus.OK, "Category deleted successfully", null);
});