import { Document, Types } from "mongoose";

export interface IDriverLocation extends Document {
    driver: Types.ObjectId;
    location: {
        type: "Point";
        coordinates: [number, number]; // [longitude, latitude]
    };
    bearing?: number; // degrees, e.g. 0-360 for map rotation
    speed?: number; // speed in m/s or km/h
    isActive: boolean; // whether driver is online and accepting tracking
    createdAt: Date;
    updatedAt: Date;
}
