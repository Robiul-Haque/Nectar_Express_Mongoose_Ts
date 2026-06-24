export interface ICategory {
    _id?: string;
    name: string;
    description?: string;
    icon?: {
        url: string;
        publicId: string;
    };
    isActive: boolean;
    isFeatured: boolean;
    sortOrder: number;
    productCount?: number;
    createdAt?: Date;
    updatedAt?: Date;
}