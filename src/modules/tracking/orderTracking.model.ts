import { Schema, model } from "mongoose";
import { IOrderTracking } from "./orderTracking.interface";

const routePointSchema = new Schema(
    {
        latitude: { type: Number, required: true },
        longitude: { type: Number, required: true },
        timestamp: { type: Date, default: Date.now }
    },
    { _id: false }
);

const orderTrackingSchema = new Schema<IOrderTracking>(
    {
        order: {
            type: Schema.Types.ObjectId,
            ref: "Order",
            required: true,
            unique: true,
            index: true
        },
        driver: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },
        status: {
            type: String,
            enum: ["assigned", "at_store", "in_transit", "delivered"],
            default: "assigned",
            index: true
        },
        startLocation: {
            type: {
                type: String,
                enum: ["Point"],
                default: "Point"
            },
            coordinates: [Number] // [longitude, latitude]
        },
        deliveryLocation: {
            type: {
                type: String,
                enum: ["Point"],
                default: "Point"
            },
            coordinates: [Number] // [longitude, latitude]
        },
        currentLocation: {
            type: {
                type: String,
                enum: ["Point"],
                default: "Point"
            },
            coordinates: [Number] // [longitude, latitude]
        },
        bearing: {
            type: Number,
            default: 0
        },
        speed: {
            type: Number,
            default: 0
        },
        estimatedDeliveryTime: {
            type: Date
        },
        routePoints: {
            type: [routePointSchema],
            default: []
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

orderTrackingSchema.index({ currentLocation: "2dsphere" });

const OrderTracking = model<IOrderTracking>("OrderTracking", orderTrackingSchema);
export default OrderTracking;
