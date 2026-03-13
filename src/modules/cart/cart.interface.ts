import { Types, Document } from "mongoose";

export interface ICartItem {
    product: Types.ObjectId;
    quantity: number;
    price: number;
    variant?: string;
}

export interface ICart extends Document {
    user: Types.ObjectId;
    items: ICartItem[];
    totalPrice: number;
    totalQuantity: number;
    createdAt?: Date;
    updatedAt?: Date;
}