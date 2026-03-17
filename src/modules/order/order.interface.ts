import { Document, Types } from "mongoose";

export type TOrderStatus = "pending" | "confirmed" | "shipped" | "delivered" | "cancelled";

export interface IShippingAddress {
    address: string;
    city: string;
    country: string;
    phone: string;
}

export interface IOrderItem {
    product: Types.ObjectId;
    name: string;
    image: string;
    price: number;
    quantity: number;
}

export interface IOrder extends Document {
    user: Types.ObjectId;
    items: IOrderItem[];
    totalQuantity: number;
    totalPrice: number;
    shippingAddress: IShippingAddress;
    status: TOrderStatus;
    createdAt: Date;
    updatedAt: Date;
}