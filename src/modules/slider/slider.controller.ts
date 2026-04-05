import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import Slider from "./slider.model";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import { uploadImageStream, deleteImage } from "../../utils/cloudinary";

export const getSlider = catchAsync(async (req: Request, res: Response) => {
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 20;
    const skip = (page - 1) * limit;

    const [items, total] = await Promise.all([
        Slider.find().skip(skip).limit(limit).sort({ createdAt: -1 }).lean(),
        Slider.countDocuments()
    ]);

    return sendResponse(res, status.OK, "Sliders fetched successfully", { total, page, limit }, items);
});

export const createSlider = catchAsync(async (req: Request, res: Response) => {
    const files = req.files as Express.Multer.File[];
    if (!files || files.length < 1) return sendResponse(res, status.BAD_REQUEST, "At least one image required");
    if (files.length > 10) return sendResponse(res, status.BAD_REQUEST, "Maximum 10 images allowed");

    const uploadResults = await Promise.all(files.map(file =>
        uploadImageStream(file.buffer, { folder: "Sliders", publicId: `slider-${Date.now()}-${Math.random().toString(36).substring(2, 6)}` })
    ));

    const imagesWithOrder = uploadResults.map((img, idx) => ({
        url: img.secure_url,
        publicId: img.public_id,
        displayOrder: idx
    }));

    const activeExists = await Slider.exists({ isActive: true });

    const slider = await Slider.create({
        ...req.body,
        images: imagesWithOrder,
        isActive: activeExists ? false : true
    });

    return sendResponse(res, status.CREATED, "Slider created successfully", null, slider);
});

export const updateSlider = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const files = req.files as Express.Multer.File[];
    const slider = await Slider.findById(id);
    if (!slider) return sendResponse(res, status.NOT_FOUND, "Slider not found");

    const updateData: any = { ...req.body };

    if (files && files.length > 0) {
        if (files.length > 10) return sendResponse(res, status.BAD_REQUEST, "Maximum 10 images per upload");

        const uploadResults = await Promise.all(files.map(file =>
            uploadImageStream(file.buffer, { folder: "Sliders", publicId: `slider-${Date.now()}-${Math.random().toString(36).substring(2, 6)}` })
        ));

        const newImages = uploadResults.map((img, index) => ({
            url: img.secure_url,
            publicId: img.public_id,
            displayOrder: slider.images.length + index
        }));

        updateData.$push = { images: { $each: newImages } };
    }

    if (updateData.isActive) {
        const activeOther = await Slider.findOne({ _id: { $ne: slider._id }, isActive: true });
        if (activeOther) return sendResponse(res, status.BAD_REQUEST, "Only one slider can be active at a time");
    }

    const updatedSlider = await Slider.findByIdAndUpdate(id, updateData, { new: true, runValidators: true });
    return sendResponse(res, status.OK, "Slider updated successfully", null, updatedSlider);
});

export const deleteSliderImage = catchAsync(async (req: Request, res: Response) => {
    const { sliderId, imageId } = req.params;

    const slider = await Slider.findById(sliderId);
    if (!slider) return sendResponse(res, status.NOT_FOUND, "Slider not found");

    const imageIndex = slider.images.findIndex((img) => img._id?.toString() === imageId);
    if (imageIndex === -1) return sendResponse(res, status.NOT_FOUND, "Image not found in this slider");

    const imageToDelete = slider.images[imageIndex];

    try {
        await deleteImage(imageToDelete.publicId);
    } catch (error) {
        console.error("[Cloudinary Delete Error]:", error);
    }

    // Remove from array
    slider.images.splice(imageIndex, 1);

    // At least one image must remain
    if (slider.images.length === 0) return sendResponse(res, status.BAD_REQUEST, "Cannot delete last image. Slider must have at least one image");
    await slider.save();

    return sendResponse(res, status.OK, "Image deleted successfully", null, { remainingImages: slider.images.length });
});

export const deleteSlider = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const slider = await Slider.findById(id);
    if (!slider) return sendResponse(res, status.NOT_FOUND, "Slider not found");

    await Promise.all(slider.images.map(img => deleteImage(img.publicId).catch(console.error)));
    await Slider.findByIdAndDelete(id);

    return sendResponse(res, status.OK, "Slider deleted successfully");
});

export const getActiveSlider = catchAsync(async (_req: Request, res: Response) => {
    const sliders = await Slider.find({ isActive: true }).select("title images actionButton animationType isActive createdAt updatedAt").lean();
    if (!sliders || sliders.length === 0) return sendResponse(res, status.NOT_FOUND, "No active sliders found", null, []);

    // Sort images by displayOrder in-memory for each slider
    sliders.forEach(slider => slider.images.sort((a, b) => a.displayOrder - b.displayOrder));

    return sendResponse(res, status.OK, "Active sliders fetched successfully", null, sliders);
});

export const sliderImageOrder = catchAsync(async (req: Request, res: Response) => {
    const { order } = req.body;

    const slider = await Slider.findOne({ "images._id": { $in: order } });
    if (!slider) return sendResponse(res, status.NOT_FOUND, "Slider not found");

    // images order update
    order.forEach((id: string, idx: number) => {
        const img = slider.images.find(img => img._id?.toString() === id);
        if (img) img.displayOrder = idx;
    });

    await slider.save();

    return sendResponse(res, status.OK, "Images display order updated successfully");
});