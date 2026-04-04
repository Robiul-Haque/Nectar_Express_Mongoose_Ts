import { Request, Response } from 'express';
import catchAsync from '../../utils/catchAsync';
import Slider from './slider.model';
import status from 'http-status';
import sendResponse from '../../utils/sendResponse';
import { deleteImage, uploadImageStream } from '../../utils/cloudinary';

export const createSlider = catchAsync(async (req: Request, res: Response) => {
    const files = req.files as Express.Multer.File[];

    if (!files || files.length === 0) return sendResponse(res, status.BAD_REQUEST, "At least one image is required");

    // Cloudinary upload
    const uploadResults = await Promise.all(
        files.map((file) =>
            uploadImageStream(file.buffer, {
                folder: "Nectar/Sliders",
                publicId: `slider-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
            })
        )
    );

    // Highest displayOrder
    const maxOrder = await Slider.findOne().sort({ displayOrder: -1 }).select("displayOrder").lean<{ displayOrder?: number }>();
    const displayOrder = (maxOrder?.displayOrder ?? 0) + 1;

    // Check if any active slider exists
    const activeSliderExists = await Slider.exists({ isActive: true });

    const newItem = await Slider.create({
        ...req.body,
        images: uploadResults.map((img) => ({
            url: img.secure_url,
            publicId: img.public_id,
        })),
        displayOrder,
        // First slider auto-active, others inactive
        isActive: activeSliderExists ? false : true,
    });

    return sendResponse(res, status.CREATED, "Slider item created successfully", null, newItem);
});

export const updateSlider = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const files = req.files as Express.Multer.File[];

    const item = await Slider.findById(id);
    if (!item) return sendResponse(res, status.BAD_REQUEST, "Slider item not found");

    const updateData: any = {};

    // Partial update
    if (req.body.title !== undefined) updateData.title = req.body.title;
    if (req.body.description !== undefined) updateData.description = req.body.description;
    if (req.body.actionButton !== undefined) updateData.actionButton = req.body.actionButton;
    if (req.body.animationType !== undefined) updateData.animationType = req.body.animationType;
    if (req.body.isActive !== undefined) updateData.isActive = req.body.isActive;

    // Append new image
    if (files && files.length > 0) {
        const uploadResults = await Promise.all(
            files.map((file) =>
                uploadImageStream(file.buffer, {
                    folder: "Nectar/Sliders",
                    publicId: `slider-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
                })
            )
        );

        const newImages = uploadResults.map((img) => ({
            url: img.secure_url,
            publicId: img.public_id,
        }));

        updateData.$push = { images: { $each: newImages } };
    }

    const updatedItem = await Slider.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).lean();
    if (!updatedItem) return sendResponse(res, status.BAD_REQUEST, "Failed to update slider item");

    return sendResponse(res, status.OK, "Slider item updated successfully", null, updatedItem);
});

export const deleteSlider = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const item = await Slider.findById(id);
    if (!item) return sendResponse(res, status.BAD_REQUEST, 'Slider item not found');

    // Delete all images from Cloudinary
    if (item.images && item.images.length > 0) {
        for (const img of item.images) {
            try {
                await deleteImage(img.publicId);
            } catch (err) {
                console.error("[Cloudinary Delete Error]", err);
            }
        }
    }

    // Delete slider item from DB
    await Slider.findByIdAndDelete(id);

    return sendResponse(res, status.OK, "Slider item deleted successfully", null, null);
});

export const getSlider = catchAsync(async (req: Request, res: Response) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const items = await Slider.find().sort({ displayOrder: 1 }).skip(skip).limit(limit).lean();
    const total = await Slider.countDocuments();

    return sendResponse(res, status.OK, "Slider items retrieved successfully", { total, page, limit }, items);
});

export const reorderSlider = catchAsync(async (req: Request, res: Response) => {
    const { order } = req.body;

    if (!Array.isArray(order) || order.length === 0) return sendResponse(res, status.BAD_REQUEST, 'Order array is required and cannot be empty');

    const bulkOps = order.map((id, index) => ({ updateOne: { filter: { _id: id }, update: { displayOrder: index + 1 } } }));
    await Slider.bulkWrite(bulkOps);

    return sendResponse(res, status.OK, "Slider items reordered successfully", null, null);
});

export const getActiveSlider = catchAsync(async (req: Request, res: Response) => {
    const items = await Slider.find({ isActive: true }).sort({ displayOrder: 1 }).select('-__v').lean();

    return sendResponse(res, status.OK, "Active sliders fetched successfully", null, items);
});

export const deleteSliderImage = catchAsync(async (req: Request, res: Response) => {
    const { sliderId, imageId } = req.params;

    const slider = await Slider.findById(sliderId);
    if (!slider) return sendResponse(res, status.BAD_REQUEST, "Slider not found");
    if (!slider.images || slider.images.length === 0) return sendResponse(res, status.BAD_REQUEST, "No images to delete");

    const imageIndex = slider.images.findIndex((img: any) => img._id?.toString() === imageId);
    if (imageIndex === -1) return sendResponse(res, status.BAD_REQUEST, "Image not found");

    const image = slider.images[imageIndex];

    try {
        await deleteImage(image.publicId);
    } catch (err) {
        return sendResponse(res, status.BAD_REQUEST, "Cloudinary delete failed");
    }

    slider.images.splice(imageIndex, 1);
    await slider.save();

    return sendResponse(res, status.OK, "Image deleted successfully");
});