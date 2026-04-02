import { Request, Response } from 'express';
import catchAsync from '../../utils/catchAsync';
import sendResponse from '../../utils/sendResponse';
import { deleteImage, uploadImageStream } from '../../utils/cloudinary';
import status from 'http-status';
import { SliderItem } from './slider.model';

export const createSliderItem = catchAsync(async (req: Request, res: Response) => {
    if (!req.file) return sendResponse(res, status.BAD_REQUEST, 'Image file is required');

    const uploadResult = await uploadImageStream(req.file.buffer, {
        folder: 'sliders',
        publicId: `slider-${Date.now()}`
    });

    // Get highest displayOrder for auto increment
    const maxOrderResult = await SliderItem.findOne({}).sort({ displayOrder: -1 }).select('displayOrder').lean<{ displayOrder: number } | null>();

    const displayOrder = (maxOrderResult?.displayOrder ?? 0) + 1;

    const newItem = await SliderItem.create({
        title: req.body.title,
        description: req.body.description,
        actionButton: req.body.actionButton,
        animationType: req.body.animationType || 'fade',
        isActive: req.body.isActive ?? true,
        image: {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        },
        displayOrder,
    });

    return sendResponse(res, status.CREATED, "Slider item created successfully", null, newItem);
});

export const updateSliderItem = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const item = await SliderItem.findById(id);
    if (!item) return sendResponse(res, status.BAD_REQUEST, 'Slider item not found');

    const updateData: any = {};

    // Only include fields that are actually sent (Partial Update)
    if (req.body.title !== undefined) updateData.title = req.body.title;
    if (req.body.description !== undefined) updateData.description = req.body.description;
    if (req.body.actionButton !== undefined) updateData.actionButton = req.body.actionButton;
    if (req.body.animationType !== undefined) updateData.animationType = req.body.animationType;
    if (req.body.isActive !== undefined) updateData.isActive = req.body.isActive;

    // Handle Image Update
    if (req.file) {
        // Delete old image from Cloudinary (important for storage optimization)
        await deleteImage(item.image.publicId);

        const uploadResult = await uploadImageStream(req.file.buffer, {
            folder: 'sliders',
            publicId: `slider-${Date.now()}`
        });

        updateData.image = {
            url: uploadResult.secure_url,
            publicId: uploadResult.public_id,
        };
    }

    const updatedItem = await SliderItem.findByIdAndUpdate(id, updateData, { new: true, runValidators: true }).lean();
    if (!updatedItem) return sendResponse(res, status.BAD_REQUEST, 'Failed to update slider item');

    return sendResponse(res, status.OK, "Slider item updated successfully", null, updatedItem);
});

export const deleteSliderItem = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;

    const item = await SliderItem.findById(id);
    if (!item) return sendResponse(res, status.BAD_REQUEST, 'Slider item not found');

    // Delete image from Cloudinary before deleting from DB
    await deleteImage(item.image.publicId);
    await SliderItem.findByIdAndDelete(id);

    return sendResponse(res, status.OK, "Slider item deleted successfully", null, null);
});

export const getSliderItems = catchAsync(async (req: Request, res: Response) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const items = await SliderItem.find().sort({ displayOrder: 1 }).skip(skip).limit(limit).lean();
    const total = await SliderItem.countDocuments();

    return sendResponse(res, status.OK, "Slider items retrieved successfully", { total, page, limit }, items);
});

export const reorderSliderItems = catchAsync(async (req: Request, res: Response) => {
    const { order } = req.body; // array of slider ids in new order

    if (!Array.isArray(order) || order.length === 0) return sendResponse(res, status.BAD_REQUEST, 'Order array is required and cannot be empty');

    const bulkOps = order.map((id, index) => ({ updateOne: { filter: { _id: id }, update: { displayOrder: index + 1 } } }));

    await SliderItem.bulkWrite(bulkOps);

    return sendResponse(res, status.OK, "Slider items reordered successfully", null, null);
});

export const getActiveSliderItems = catchAsync(async (req: Request, res: Response) => {
    const items = await SliderItem.find({ isActive: true }).sort({ displayOrder: 1 }).select('-__v').lean();

    return sendResponse(res, status.OK, "Active sliders fetched successfully", null, items);
});