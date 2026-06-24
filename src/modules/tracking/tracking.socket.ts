import { Server, Socket } from "socket.io";
import mongoose from "mongoose";
import { updateLocationHelper } from "./tracking.controller";
import Order from "../order/order.model";

interface SocketPayload {
    sub: string;
    role: "user" | "admin" | "driver";
    provider?: string;
    v?: number;
}

interface AuthenticatedSocket extends Socket {
    user?: SocketPayload;
}

// In-memory rate limiter for tracking socket events
const trackingRateLimits = new Map<string, Map<string, { count: number; resetAt: number }>>();

function checkTrackingRateLimit(socketId: string, event: string, maxRequests: number, windowMs: number): boolean {
    const now = Date.now();
    let limits = trackingRateLimits.get(socketId);
    if (!limits) {
        limits = new Map();
        trackingRateLimits.set(socketId, limits);
    }
    let eventLimit = limits.get(event);
    if (!eventLimit || now > eventLimit.resetAt) {
        eventLimit = { count: 0, resetAt: now + windowMs };
        limits.set(event, eventLimit);
    }
    eventLimit.count++;
    if (eventLimit.count > maxRequests) return false;
    return true;
}

export const registerTrackingHandlers = (io: Server, socket: AuthenticatedSocket) => {
    // Cleanup rate limit data when socket disconnects
    socket.on("disconnect", () => {
        trackingRateLimits.delete(socket.id);
    });
    // 1. Client joins room to listen to live tracking of an order
    socket.on(
        "joinOrderTrack",
        async (
            { orderId }: { orderId: string },
            callback?: (response: { status: string; message: string }) => void
        ) => {
            try {
                if (!checkTrackingRateLimit(socket.id, "joinOrderTrack", 20, 60000)) {
                    return callback?.({ status: "error", message: "Rate limit exceeded. Please slow down." });
                }
                if (!mongoose.Types.ObjectId.isValid(orderId)) {
                    socket.emit("error", "Invalid orderId");
                    return callback?.({ status: "error", message: "Invalid orderId" });
                }

                const userId = socket.user?.sub;
                const userRole = socket.user?.role;

                if (!userId) {
                    socket.emit("error", "Unauthorized");
                    return callback?.({ status: "error", message: "Unauthorized" });
                }

                // Verify order exists
                const order = await Order.findById(orderId).select("user driver").exec();
                if (!order) {
                    socket.emit("error", "Order not found");
                    return callback?.({ status: "error", message: "Order not found" });
                }

                // Permission check: User must be customer who purchased, assigned driver, or admin
                const isCustomer = userRole === "user" && order.user.toString() === userId;
                const isAssignedDriver = userRole === "driver" && order.driver?.toString() === userId;
                const isAdmin = userRole === "admin";

                if (!isCustomer && !isAssignedDriver && !isAdmin) {
                    socket.emit("error", "Access denied to track this order");
                    return callback?.({ status: "error", message: "Access denied" });
                }

                const roomName = `order:track:${orderId}`;
                socket.join(roomName);
                console.log(`🔵 Socket ${socket.id} (User: ${userId}) joined tracking room: ${roomName}`);

                return callback?.({
                    status: "success",
                    message: `Successfully joined tracking room: ${roomName}`
                });
            } catch (error) {
                console.error("❌ joinOrderTrack error:", error);
                socket.emit("error", "Failed to join tracking room");
                return callback?.({ status: "error", message: "Internal server error" });
            }
        }
    );

    // 2. Driver client broadcasts real-time GPS coordinates via WebSocket
    socket.on(
        "driver:update-location",
        async (
            payload: {
                latitude: number;
                longitude: number;
                bearing?: number;
                speed?: number;
                orderId?: string;
            },
            callback?: (response: { status: string; message: string }) => void
        ) => {
            try {
                if (!checkTrackingRateLimit(socket.id, "driver:update-location", 60, 60000)) {
                    return callback?.({ status: "error", message: "Rate limit exceeded. Please slow down." });
                }
                const driverId = socket.user?.sub;
                const userRole = socket.user?.role;

                if (!driverId || userRole !== "driver") {
                    socket.emit("error", "Unauthorized: Only drivers can transmit location data");
                    return callback?.({ status: "error", message: "Unauthorized" });
                }

                const { latitude, longitude, bearing, speed, orderId } = payload;

                if (typeof latitude !== "number" || typeof longitude !== "number") {
                    socket.emit("error", "Coordinates latitude and longitude must be numbers");
                    return callback?.({ status: "error", message: "Invalid parameters" });
                }

                // Execute shared database updates and real-time room propagation
                await updateLocationHelper(
                    driverId,
                    latitude,
                    longitude,
                    bearing,
                    speed,
                    orderId,
                    io
                );

                return callback?.({ status: "success", message: "Location parsed and broadcasted" });
            } catch (error) {
                console.error("❌ driver:update-location error:", error);
                socket.emit("error", "Failed to process driver location update");
                return callback?.({ status: "error", message: "Internal server error" });
            }
        }
    );
};
