import { Request, Response } from "express";
import { Server } from "socket.io";
import mongoose from "mongoose";
import status from "http-status";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import DriverLocation from "./driverLocation.model";
import OrderTracking from "./orderTracking.model";
import Order from "../order/order.model";
import User from "../user/user.model";

/**
 * Shared helper to update a driver's location and propagate it to the active order room.
 * Used by both Socket.IO and REST API HTTP fallbacks.
 */
export const updateLocationHelper = async (
    driverId: string,
    latitude: number,
    longitude: number,
    bearing?: number,
    speed?: number,
    orderId?: string,
    io?: Server
) => {
    // 1. Update DriverLocation collection (preserve existing isActive status)
    const driverLoc = await DriverLocation.findOneAndUpdate(
        { driver: new mongoose.Types.ObjectId(driverId) },
        {
            $set: {
                location: {
                    type: "Point",
                    coordinates: [longitude, latitude] // GeoJSON coordinates format is [longitude, latitude]
                },
                bearing: bearing || 0,
                speed: speed || 0
            },
            $setOnInsert: { isActive: true } // only set to true on first creation
        },
        { upsert: true, new: true }
    );

    // 2. If there is an active order being tracked, update OrderTracking
    if (orderId && mongoose.Types.ObjectId.isValid(orderId)) {
        const orderObjectId = new mongoose.Types.ObjectId(orderId);
        
        // Find OrderTracking and verify driver is the one assigned
        const tracking = await OrderTracking.findOne({ order: orderObjectId, driver: new mongoose.Types.ObjectId(driverId) });
        
        if (tracking && tracking.status !== "delivered") {
            // Update current location and push route history point
            await OrderTracking.updateOne(
                { order: orderObjectId },
                {
                    $set: {
                        currentLocation: {
                            type: "Point",
                            coordinates: [longitude, latitude]
                        },
                        bearing: bearing || 0,
                        speed: speed || 0
                    },
                    $push: {
                        routePoints: {
                            latitude,
                            longitude,
                            timestamp: new Date()
                        }
                    }
                }
            );

            // 3. Broadcast real-time location update to the order's tracking room
            if (io) {
                io.to(`order:track:${orderId}`).emit("order:tracking-update", {
                    orderId,
                    latitude,
                    longitude,
                    bearing: bearing || 0,
                    speed: speed || 0,
                    status: tracking.status,
                    updatedAt: new Date()
                });
            }
        }
    }

    return driverLoc;
};

/**
 * HTTP Fallback to update driver location
 */
export const updateLocation = catchAsync(async (req: Request, res: Response) => {
    const driverId = req.user?.sub;
    if (!driverId) {
        return sendResponse(res, status.UNAUTHORIZED, "Driver not authenticated");
    }

    const { latitude, longitude, bearing, speed, orderId } = req.body;
    const io = req.app.get("io") as Server;

    const result = await updateLocationHelper(
        driverId,
        latitude,
        longitude,
        bearing,
        speed,
        orderId,
        io
    );

    return sendResponse(res, status.OK, "Driver location updated successfully", null, result);
});

/**
 * Assign a driver to an order and initialize order tracking
 */
export const assignDriver = catchAsync(async (req: Request, res: Response) => {
    const { orderId, driverId, startLocation, deliveryLocation } = req.body;

    // Verify order exists
    const order = await Order.findById(orderId);
    if (!order) {
        return sendResponse(res, status.NOT_FOUND, "Order not found");
    }

    // Verify driver exists and has driver role
    const driverUser = await User.findOne({ _id: driverId, role: "driver" });
    if (!driverUser) {
        return sendResponse(res, status.BAD_REQUEST, "Driver not found or invalid driver role");
    }

    // Assign driver to Order document (backward compatible change)
    order.driver = new mongoose.Types.ObjectId(driverId);
    // Automatically transition status to 'shipped' when assigned for delivery
    order.orderStatus = "shipped";
    await order.save();

    // Prepare geo locations if provided
    const startPoint = startLocation
        ? { type: "Point" as const, coordinates: [startLocation.longitude, startLocation.latitude] }
        : undefined;
    const deliveryPoint = deliveryLocation
        ? { type: "Point" as const, coordinates: [deliveryLocation.longitude, deliveryLocation.latitude] }
        : undefined;

    // Upsert the OrderTracking details
    const orderTracking = await OrderTracking.findOneAndUpdate(
        { order: new mongoose.Types.ObjectId(orderId) },
        {
            driver: new mongoose.Types.ObjectId(driverId),
            status: "assigned",
            startLocation: startPoint,
            deliveryLocation: deliveryPoint,
            routePoints: [],
            estimatedDeliveryTime: new Date(Date.now() + 45 * 60 * 1000) // Default estimate: 45 mins
        },
        { upsert: true, new: true }
    );

    // Notify user about driver assignment via Socket.IO
    const io = req.app.get("io") as Server;
    if (io) {
        io.to(order.user.toString()).emit("order:driver-assigned", {
            orderId,
            driver: {
                name: driverUser.name,
                avatar: driverUser.avatar?.url || null
            },
            status: "assigned"
        });
    }

    return sendResponse(res, status.OK, "Driver assigned to order and tracking initialized", null, orderTracking);
});

/**
 * Update delivery tracking status (e.g. in_transit, delivered)
 */
export const updateTrackingStatus = catchAsync(async (req: Request, res: Response) => {
    const { orderId } = req.params;
    const { status: trackingStatus, estimatedDeliveryTime } = req.body;
    const userId = req.user?.sub;
    const userRole = req.user?.role;

    const tracking = await OrderTracking.findOne({ order: new mongoose.Types.ObjectId(orderId as string) });
    if (!tracking) {
        return sendResponse(res, status.NOT_FOUND, "Tracking details not found for this order");
    }

    // Authorization check: Only assigned driver or admin can update status
    if (userRole !== "admin" && tracking.driver.toString() !== userId) {
        return sendResponse(res, status.FORBIDDEN, "You are not authorized to update tracking details for this order");
    }

    // Update status
    tracking.status = trackingStatus;
    if (estimatedDeliveryTime) {
        tracking.estimatedDeliveryTime = new Date(estimatedDeliveryTime);
    }
    await tracking.save();

    // If order is completed/delivered, sync order status as well
    if (trackingStatus === "delivered") {
        await Order.findByIdAndUpdate(orderId, { orderStatus: "delivered", paymentStatus: "paid" });
    }

    // Broadcast status change to tracking room
    const io = req.app.get("io") as Server;
    if (io) {
        io.to(`order:track:${orderId}`).emit("order:status-update", {
            orderId,
            status: trackingStatus,
            estimatedDeliveryTime: tracking.estimatedDeliveryTime
        });
    }

    return sendResponse(res, status.OK, `Order tracking status updated to ${trackingStatus}`, null, tracking);
});

/**
 * Get current online driver location (Admin/Internal use)
 */
export const getDriverLocation = catchAsync(async (req: Request, res: Response) => {
    const { driverId } = req.params;

    const location = await DriverLocation.findOne({ driver: new mongoose.Types.ObjectId(driverId as string) })
        .populate("driver", "name email avatar")
        .exec();

    if (!location) {
        return sendResponse(res, status.NOT_FOUND, "No active location tracking record found for this driver");
    }

    return sendResponse(res, status.OK, "Driver location retrieved successfully", null, location);
});

/**
 * Get active tracking sequence for an order (Customer / Driver / Admin)
 */
export const getOrderTracking = catchAsync(async (req: Request, res: Response) => {
    const { orderId } = req.params;
    const userId = req.user?.sub;
    const userRole = req.user?.role;

    const tracking = await OrderTracking.findOne({ order: new mongoose.Types.ObjectId(orderId as string) })
        .populate("driver", "name email avatar location phone")
        .populate("order", "user totalPrice shippingAddress orderStatus");

    if (!tracking) {
        return sendResponse(res, status.NOT_FOUND, "No active tracking details found for this order");
    }

    const orderDoc = tracking.order as any;

    // Authorization check: User must be customer who purchased, assigned driver, or admin
    if (
        userRole !== "admin" &&
        tracking.driver._id.toString() !== userId &&
        orderDoc.user.toString() !== userId
    ) {
        return sendResponse(res, status.FORBIDDEN, "You do not have permission to track this order");
    }

    return sendResponse(res, status.OK, "Order tracking retrieved successfully", null, tracking);
});

/**
 * Toggle driver active (online/offline) status
 */
export const toggleDriverActiveStatus = catchAsync(async (req: Request, res: Response) => {
    const driverId = req.user?.sub;
    if (!driverId) {
        return sendResponse(res, status.UNAUTHORIZED, "Driver not authenticated");
    }

    const { isActive } = req.body;

    const driverLoc = await DriverLocation.findOneAndUpdate(
        { driver: new mongoose.Types.ObjectId(driverId) },
        { $set: { isActive } },
        { upsert: true, new: true }
    );

    return sendResponse(
        res,
        status.OK,
        `Driver status updated to ${isActive ? "online" : "offline"}`,
        null,
        driverLoc
    );
});

/**
 * Get nearby active drivers using MongoDB 2dsphere index matching
 */
export const getNearbyDrivers = catchAsync(async (req: Request, res: Response) => {
    const { latitude, longitude, maxDistance } = req.query;

    const lat = parseFloat(latitude as string);
    const lng = parseFloat(longitude as string);
    const dist = maxDistance ? parseInt(maxDistance as string) : 5000; // meters, default 5km

    const drivers = await DriverLocation.find({
        isActive: true,
        location: {
            $nearSphere: {
                $geometry: {
                    type: "Point",
                    coordinates: [lng, lat]
                },
                $maxDistance: dist
            }
        }
    }).populate("driver", "name email avatar location phone");

    return sendResponse(res, status.OK, "Nearby active drivers retrieved successfully", null, drivers);
});
