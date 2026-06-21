import catchAsync from "../../utils/catchAsync";
import { Request, Response } from "express";
import slugify from "slugify";
import httpStatus from "http-status";
import Product from "./product.model";
import { sendPushNotification, TPushPayload } from "../../utils/pushNotification";
import sendResponse from "../../utils/sendResponse";
import { deleteImage, uploadImageStream } from "../../utils/cloudinary";
import logger from "../../utils/logger";
import { deletePattern } from "../../utils/redis";

export const createProduct = catchAsync(async (req: Request, res: Response) => {
    const payload: any = req.body;

    // Generate slug
    const slug = slugify(payload.name, { lower: true, strict: true });

    const exists = await Product.findOne({ $or: [{ slug }, { sku: payload.sku }] }).lean();
    if (exists) return sendResponse(res, httpStatus.CONFLICT, "Product with this name or SKU already exists");

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

    // Invalidate product caches (list and detail views)
    await deletePattern("cache:/api/v1/product*");

    const pushPayload: TPushPayload = {
        title: "🆕 New Product Available!",
        body: `${product.name} is now available. Grab yours today!`,
        ...(product.image?.url && { image: product.image.url })
    };

    // Send push (non-blocking)
    sendPushNotification(pushPayload).catch(err => console.error("Push Notification Error:", err?.message || err));

    return sendResponse(res, httpStatus.CREATED, "Product created successfully", { notification: "Push notification triggered" }, product);
});

export const getAllProducts = catchAsync(async (req: Request, res: Response) => {
    const { search, category, brand, isFeatured, isActive, page = 1, limit = 10, sort } = req.query;

    const filter: any = {};
    if (search) {
        filter.$or = [
            { name: { $regex: search, $options: "i" } },
            { sku: { $regex: search, $options: "i" } }
        ];
    }
    if (category) filter.category = category;
    if (brand) filter.brand = brand;
    if (isFeatured !== undefined) filter.isFeatured = isFeatured === "true";
    if (isActive !== undefined) filter.isActive = isActive === "true";

    const skip = (Number(page) - 1) * Number(limit);
    const limitNum = Number(limit);

    let sortOptions: any = { createdAt: -1 };
    if (sort === "price_low") sortOptions = { price: 1 };
    if (sort === "price_high") sortOptions = { price: -1 };

    const [products, total] = await Promise.all([
        Product.find(filter)
            .populate("category", "name")
            .populate("brand", "name")
            .select("-nutrition")
            .sort(sortOptions)
            .skip(skip)
            .limit(limitNum)
            .lean(),
        Product.countDocuments(filter)
    ]);

    const pagination = {
        total,
        page: Number(page),
        limit: limitNum
    };

    return sendResponse(res, httpStatus.OK, "Products retrieved successfully", pagination, products);
});

export const getAdminProducts = catchAsync(async (req: Request, res: Response) => {
    const { search, filter: tabFilter, page = 1, limit = 10 } = req.query;

    const query: any = {};
    
    // Search by Name, SKU or Category
    if (search) {
        query.$or = [
            { name: { $regex: search, $options: "i" } },
            { sku: { $regex: search, $options: "i" } }
        ];
    }

    // Tab Filters
    if (tabFilter === "low_stock") query.stock = { $gt: 0, $lt: 10 };
    else if (tabFilter === "out_of_stock") query.stock = 0;
    else if (tabFilter === "active") query.isActive = true;
    else if (tabFilter === "inactive") query.isActive = false;

    const skip = (Number(page) - 1) * Number(limit);
    const limitNum = Number(limit);

    const products = await Product.find(query)
        .populate("category", "name")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .lean();

    const total = await Product.countDocuments(query);

    const pagination = {
        total,
        page: Number(page),
        limit: limitNum
    };

    return sendResponse(res, httpStatus.OK, "Admin products retrieved successfully", pagination, products);
});

export const getProductStats = catchAsync(async (_req: Request, res: Response) => {
    const stats = await Product.aggregate([
        {
            $facet: {
                totalProducts: [{ $count: "count" }],
                lowStock: [
                    { $match: { stock: { $gt: 0, $lt: 10 } } },
                    { $count: "count" }
                ],
                outOfStock: [
                    { $match: { stock: 0 } },
                    { $count: "count" }
                ],
                valuation: [
                    {
                        $group: {
                            _id: null,
                            total: { $sum: { $multiply: ["$price", "$stock"] } }
                        }
                    }
                ],
                availableCount: [
                    { $match: { stock: { $gt: 0 } } },
                    { $count: "count" }
                ]
            }
        }
    ]);

    const result = stats[0];
    const totalCount = result.totalProducts[0]?.count || 0;
    const lowStockCount = result.lowStock[0]?.count || 0;
    const outOfStockCount = result.outOfStock[0]?.count || 0;
    const totalValuation = result.valuation[0]?.total || 0;
    const availableCount = result.availableCount[0]?.count || 0;

    const formattedStats = {
        totalProducts: totalCount,
        lowStockAlerts: {
            total: lowStockCount + outOfStockCount,
            outOfStock: outOfStockCount
        },
        stockHealth: totalCount > 0 ? Math.round((availableCount / totalCount) * 100) : 0,
        totalValuation: Number(totalValuation.toFixed(2))
    };

    return sendResponse(res, httpStatus.OK, "Product stats retrieved successfully", null, formattedStats);
});

export const getSingleProduct = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const product = await Product.findById(id)
        .populate("category", "name")
        .populate("brand", "name")
        .lean();

    if (!product) {
        return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");
    }

    return sendResponse(res, httpStatus.OK, "Product retrieved successfully", null, product);
});

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

    if (req.body.sku) payload.sku = req.body.sku;
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

    // Invalidate product caches (list and detail views)
    await deletePattern("cache:/api/v1/product*");

    return sendResponse(res, httpStatus.OK, "Product updated successfully", null, updatedProduct);
});

export const deleteProduct = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const deleted = await Product.findByIdAndDelete(id).lean();
    if (!deleted) return sendResponse(res, httpStatus.NOT_FOUND, "Product not found");

    // Invalidate product caches (list and detail views)
    await deletePattern("cache:/api/v1/product*");

    return sendResponse(res, httpStatus.OK, "Product deleted successfully");
});