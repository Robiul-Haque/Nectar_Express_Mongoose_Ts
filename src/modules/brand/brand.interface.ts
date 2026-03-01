export interface IBrand {
    _id?: string;
    name: string;
    logo?: {
        url: {
            type: String,
            default: null
        },
        publicId: {
            type: String,
            default: null,
        }
    };
    isActive: boolean;
    createdAt?: Date;
    updatedAt?: Date;
}