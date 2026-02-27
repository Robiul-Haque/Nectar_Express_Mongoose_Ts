export interface IBrand {
    _id?: string;
    name: string;
    slug: string;
    logo?: string;
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}