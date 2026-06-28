export interface IBrand {
    _id?: string;
    name: string;
    logo?: {
        url: string;
        publicId: string;
    };
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}