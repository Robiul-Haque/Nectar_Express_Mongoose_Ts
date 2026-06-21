import { Schema, model } from "mongoose";
import { IDriverLocation } from "./driverLocation.interface";

const driverLocationSchema = new Schema<IDriverLocation>(
    {
        driver: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true,
            unique: true,
            index: true
        },
        location: {
            type: {
                type: String,
                enum: ["Point"],
                required: true,
                default: "Point"
            },
            coordinates: {
                type: [Number], // [longitude, latitude]
                required: true
            }
        },
        bearing: {
            type: Number,
            default: 0
        },
        speed: {
            type: Number,
            default: 0
        },
        isActive: {
            type: Boolean,
            default: true,
            index: true
        }
    },
    {
        timestamps: true,
        versionKey: false
    }
);

// 2dsphere index for geo queries
driverLocationSchema.index({ location: "2dsphere" });

const DriverLocation = model<IDriverLocation>("DriverLocation", driverLocationSchema);
export default DriverLocation;
