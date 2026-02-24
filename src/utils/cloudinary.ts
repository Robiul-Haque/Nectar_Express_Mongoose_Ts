import cloudinary from "../config/cloudinary.config";
import { UploadApiResponse } from "cloudinary";

interface UploadOptions {
    folder: string;
    publicId?: string;
}

export const uploadImageStream = (fileBuffer: Buffer,options: UploadOptions): Promise<UploadApiResponse> => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            {
                folder: options.folder,
                public_id: options.publicId,
                resource_type: "image",
                transformation: [
                    { quality: "auto:good" },
                    { fetch_format: "auto" },
                ],
            },
            (error, result) => {
                if (error) return reject(new Error(`Cloudinary Upload Failed: ${error.message}`));
                resolve(result as UploadApiResponse);
            }
        );

        stream.end(fileBuffer);
    });
};

export const deleteImage = async (publicId: string) => {
    try {
        await cloudinary.uploader.destroy(publicId);
    } catch (error: any) {
        throw new Error(`Cloudinary Delete Failed: ${error.message}`);
    }
};