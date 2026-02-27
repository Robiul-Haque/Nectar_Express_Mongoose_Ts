export interface ICategory {
    _id?: string;
    name: string;
    description?: string;
    icon?: string;
    image?: string;
    parent?: string | ICategory | null;
    isActive: boolean;
    isFeatured: boolean;
    sortOrder: number;
    createdAt?: Date;
    updatedAt?: Date;
}