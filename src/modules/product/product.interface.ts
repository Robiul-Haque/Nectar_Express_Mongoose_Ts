import { Types } from "mongoose";

export type MeasurementUnit = "kg" | "g" | "pc";

export interface IProductImage {
    url: string;
    publicId: string;
}

export interface IMeasurement {
    value: number;
    unit: MeasurementUnit;
}

export interface IProduct {
    name: string;
    slug: string;
    description?: string;
    measurement: IMeasurement;
    price: number;
    discountPrice?: number;
    stock: number;
    images: IProductImage;
    category: Types.ObjectId;
    brand: Types.ObjectId;
    nutrition?: string;
    averageRating: number;
    totalReviews: number;
    isFeatured: boolean;
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}