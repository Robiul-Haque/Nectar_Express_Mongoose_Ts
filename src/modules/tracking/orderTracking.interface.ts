import { Document, Types } from "mongoose";

export interface IRoutePoint {
    latitude: number;
    longitude: number;
    timestamp: Date;
}

export interface IOrderTracking extends Document {
    order: Types.ObjectId;
    driver: Types.ObjectId;
    status: "assigned" | "at_store" | "in_transit" | "delivered";
    startLocation?: {
        type: "Point";
        coordinates: [number, number]; // [longitude, latitude]
    };
    deliveryLocation?: {
        type: "Point";
        coordinates: [number, number]; // [longitude, latitude]
    };
    currentLocation?: {
        type: "Point";
        coordinates: [number, number]; // [longitude, latitude]
    };
    bearing?: number;
    speed?: number;
    estimatedDeliveryTime?: Date;
    routePoints: IRoutePoint[];
    createdAt: Date;
    updatedAt: Date;
}
