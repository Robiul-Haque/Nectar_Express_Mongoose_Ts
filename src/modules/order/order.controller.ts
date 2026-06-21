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

        return sendResponse(res, status.CREATED, "Order create successfully", null, order);

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
    const { search, orderStatus, page = 1, limit = 10 } = req.query;

    const pageNum = Number(page);
    const limitNum = Number(limit);
    const skip = (pageNum - 1) * limitNum;

    const pipeline: any[] = [];

    // Filter Match
    const matchQuery: any = {};
    if (orderStatus && orderStatus !== "All Orders") {
        matchQuery.orderStatus = (orderStatus as string).toLowerCase();
    }

    if (search) {
        matchQuery.$or = [
            { _id: mongoose.Types.ObjectId.isValid(search as string) ? new mongoose.Types.ObjectId(search as string) : undefined },
            { "shippingAddress.phone": { $regex: search, $options: "i" } }
        ].filter(Boolean);
    }

    if (Object.keys(matchQuery).length > 0) pipeline.push({ $match: matchQuery });

    // Sort
    pipeline.push({ $sort: { createdAt: -1 } });

    // Pagination and Data Shaping
    pipeline.push({
        $facet: {
            metadata: [{ $count: "total" }],
            data: [
                { $skip: skip },
                { $limit: limitNum },
                {
                    $lookup: {
                        from: "users",
                        localField: "user",
                        foreignField: "_id",
                        as: "customerInfo"
                    }
                },
                { $unwind: "$customerInfo" },
                {
                    $addFields: {
                        customer: {
                            name: "$customerInfo.name",
                            email: "$customerInfo.email",
                            initials: {
                                $reduce: {
                                    input: { $slice: [{ $split: ["$customerInfo.name", " "] }, 2] },
                                    initialValue: "",
                                    in: { $concat: ["$$value", { $substr: ["$$this", 0, 1] }] }
                                }
                            }
                        },
                        itemsCount: { $size: "$items" },
                        orderId: "$_id"
                    }
                },
                { $project: { customerInfo: 0 } }
            ]
        }
    });

    const result = await Order.aggregate(pipeline);
    const data = result[0].data;
    const total = result[0].metadata[0]?.total || 0;

    const pagination = {
        total,
        page: pageNum,
        limit: limitNum,
        totalPages: Math.ceil(total / limitNum)
    };

    return sendResponse(res, status.OK, "Orders retrieved successfully", pagination, data);
});

export const cancelOrder = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const userRole = req.user!.role;

    const session = await mongoose.startSession();
    try {
        session.startTransaction();

        const order = await Order.findById(req.params.id).session(session);
        if (!order) {
            await session.abortTransaction();
            return sendResponse(res, status.NOT_FOUND, "Order not found");
        }

        // BOLA / IDOR ownership validation
        if (order.user.toString() !== userId && userRole !== "admin") {
            await session.abortTransaction();
            return sendResponse(res, status.FORBIDDEN, "You do not have permission to cancel this order");
        }

        if (order.orderStatus !== "pending") {
            await session.abortTransaction();
            return sendResponse(res, status.BAD_REQUEST, "Order cannot be cancelled");
        }

        order.orderStatus = "cancelled";

        // Restore stock using bulkWrite in the transaction session
        await Product.bulkWrite(
            order.items.map((i) => ({
                updateOne: {
                    filter: { _id: i.product },
                    update: { $inc: { stock: i.quantity } }
                }
            })),
            { session }
        );

        await order.save({ session });
        await session.commitTransaction();

        return sendResponse(res, status.OK, "Order cancelled successfully", null, order);
    } catch (error) {
        await session.abortTransaction();
        throw error;
    } finally {
        session.endSession();
    }
});

export const updateOrderStatus = catchAsync(async (req: Request, res: Response) => {
    const { id } = req.params;
    const { orderStatus: newStatus } = req.body;

    const allowedStatus = ["pending", "confirmed", "shipped", "delivered", "cancelled"];
    if (!allowedStatus.includes(newStatus)) return sendResponse(res, status.BAD_REQUEST, "Invalid status");

    // Find order + populate product (for image) & update status
    const order = await Order.findById(id).populate("items.product", "name image").select("+user");
    if (!order) return sendResponse(res, status.NOT_FOUND, "Order not found");
    if (order.orderStatus === newStatus) return sendResponse(res, status.BAD_REQUEST, "Status already updated");
    order.orderStatus = newStatus;
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
