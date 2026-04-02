import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import mongoose from "mongoose";
import Cart from "../cart/cart.model";
import sendResponse from "../../utils/sendResponse";
import Order from "./order.model";
import Product from "../product/product.model";
import status from "http-status";
import { sendPushNotification } from "../../utils/pushNotification";

export const createOrder = catchAsync(async (req: Request, res: Response) => {
    const session = await mongoose.startSession();

    try {
        session.startTransaction();

        const userId = req.user!.sub;
        const { paymentIntentId, shippingAddress } = req.body;

        const cart = await Cart.findOne({ user: userId }).populate("items.product", "name image stock isActive price discountPrice").session(session);

        if (!cart || cart.items.length === 0) {
            await session.abortTransaction();
            return sendResponse(res, status.BAD_REQUEST, "Cart is empty");
        }

        const orderItems: any[] = [];

        for (const item of cart.items) {
            const product: any = item.product;

            if (!product || !product.isActive || product.stock < item.quantity) {
                await session.abortTransaction();
                return sendResponse(res, status.BAD_REQUEST, "Stock issue");
            }

            const finalPrice = product.discountPrice ?? product.price;

            orderItems.push({
                product: product._id,
                name: product.name,
                image: product.image?.url || "",
                price: finalPrice,
                quantity: item.quantity
            });
        }

        const [order] = await Order.create([{
            user: userId,
            items: orderItems,
            totalQuantity: cart.totalQuantity,
            totalPrice: orderItems.reduce((sum, i) => sum + i.price * i.quantity, 0),
            shippingAddress,
            paymentStatus: "paid",
            paymentIntentId
        }], { session });

        for (const item of orderItems) {
            const updated = await Product.updateOne(
                { _id: item.product, stock: { $gte: item.quantity } },
                { $inc: { stock: -item.quantity } },
                { session }
            );

            if (updated.modifiedCount === 0) {
                await session.abortTransaction();
                return sendResponse(res, 400, "Stock conflict");
            }
        }

        await Cart.deleteOne({ user: userId }).session(session);
        await session.commitTransaction();

        return sendResponse(res, status.CREATED, "Order confirmed", null, order);

    } catch (error) {
        await session.abortTransaction();
        throw error;
    } finally {
        session.endSession();
    }
});

export const getMyOrders = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;

    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const orders = await Order.find({ user: userId }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
    const total = await Order.countDocuments({ user: userId });

    return sendResponse(res, status.OK, "Orders retrieved", { total, page, limit }, orders);
});

export const getSingleOrder = catchAsync(async (req: Request, res: Response) => {
    const order = await Order.findById(req.params.id).lean();
    if (!order) return sendResponse(res, status.NOT_FOUND, "Order not found");

    return sendResponse(res, status.OK, "Order retrieved", null, order);
});

export const getAllOrders = catchAsync(async (req: Request, res: Response) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const orders = await Order.find().populate("user", "name email").sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
    const total = await Order.countDocuments();

    return sendResponse(res, status.OK, "All orders", { total, page, limit }, orders);
});

export const cancelOrder = catchAsync(async (req: Request, res: Response) => {
    const order = await Order.findById(req.params.id);
    if (!order) return sendResponse(res, status.NOT_FOUND, "Order not found");

    if (order.status !== "pending") return sendResponse(res, status.BAD_REQUEST, "Order cannot be cancelled");
    order.status = "cancelled";

    await Product.bulkWrite(
        order.items.map((i) => ({
            updateOne: {
                filter: { _id: i.product },
                update: { $inc: { stock: i.quantity } }
            }
        }))
    );

    await order.save();

    return sendResponse(res, status.OK, "Order cancelled", null, order);
});

export const updateOrderStatus = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { status: newStatus } = req.body;

    const allowedStatus = ["pending", "confirmed", "shipped", "delivered", "cancelled"];
    if (!allowedStatus.includes(newStatus)) return sendResponse(res, status.BAD_REQUEST, "Invalid status");

    // Find order + populate product (for image) & update status
    const order = await Order.findById(id).populate("items.product", "name image").select("+user");
    if (!order) return sendResponse(res, status.NOT_FOUND, "Order not found");
    if (order.status === newStatus) return sendResponse(res, status.BAD_REQUEST, "Status already updated");
    order.status = newStatus;
    await order.save();

    const userId = order.user?.toString();

    // Product image (first item)
    let image: string | undefined;
    if (order.items?.length > 0) {
        const firstProduct: any = order.items[0].product;
        image = firstProduct?.image?.url;
    }

    // Status message
    const statusMessageMap: Record<string, string> = {
        pending: "Your order is pending.",
        confirmed: "Your order has been confirmed ✅",
        shipped: "Your order has been shipped 🚚",
        delivered: "Your order has been delivered 🎉",
        cancelled: "Your order has been cancelled ❌"
    };

    const message = statusMessageMap[newStatus] || "Your order status has been updated";

    // Send push notification (non-blocking)
    if (userId) sendPushNotification({ title: "📦 Order Update", body: message, image }, { userIds: [userId] }).catch(err => console.error("Push Notification Error:", err));

    return sendResponse(res, status.OK, "Order status updated successfully", null, order);
});