export interface ICategory {
    _id?: string;
    name: string;
    description?: string;
    icon?: {
        url: string;
        publicId: string;
    };
    image?: string;
    level?: number;
    isActive: boolean;
    isFeatured: boolean;
    sortOrder: number;
    productCount?: number;
    createdAt?: Date;
    updatedAt?: Date;
}