import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import stripe from "../../config/stripe.config";
import { env } from "../../config/env";
import mongoose from "mongoose";
import Cart from "../cart/cart.model";
import Order from "../order/order.model";
import Product from "../product/product.model";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

export const stripeWebhook = catchAsync(async (req: Request, res: Response) => {
    const sig = req.headers["stripe-signature"] as string;

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, env.STRIPE_WEBHOOK_SECRET);
    } catch (err: any) {
        console.error("Webhook signature error:", err.message);
        return sendResponse(res, status.BAD_REQUEST, "Invalid webhook signature", null, null);
    }

    // Only handle success event
    if (event.type !== "payment_intent.succeeded") return sendResponse(res, status.OK, "Event ignored", null, { received: true });

    const paymentIntent: any = event.data.object;
    const { orderId } = paymentIntent.metadata;

    const session = await mongoose.startSession();

    try {
        session.startTransaction();

        const order = await Order.findById(orderId).session(session);
        if (!order) throw new Error("Order not found");

        // Idempotency
        if (order.paymentStatus === "paid") {
            await session.abortTransaction();

            return sendResponse(res, status.OK, "Already processed", null, { received: true });
        }

        // Batch product fetch
        const productIds = order.items.map(i => i.product);
        const products = await Product.find({ _id: { $in: productIds } }).select("stock").lean().session(session);
        const productMap = new Map(products.map(p => [p._id.toString(), p]));

        // Stock check + update
        for (const item of order.items) {
            const product = productMap.get(item.product.toString());
            if (!product) throw new Error("Product not found");

            if (product.stock < item.quantity) throw new Error(`Stock conflict for ${item.name}`);

            const updated = await Product.updateOne(
                { _id: item.product, stock: { $gte: item.quantity } },
                { $inc: { stock: -item.quantity } },
                { session }
            );

            if (updated.modifiedCount === 0) throw new Error(`Stock race condition for ${item.name}`);
        }

        // Update order
        order.status = "pending";
        order.paymentStatus = "paid";
        order.paymentIntentId = paymentIntent.id;

        await order.save({ session });

        // Clear cart
        await Cart.deleteOne({ user: order.user }).session(session);

        await session.commitTransaction();

        return sendResponse(res, status.OK, "Payment processed successfully", null, { received: true });
    } catch (err: any) {
        await session.abortTransaction();
        console.error("Webhook error:", err);

        // Refund
        try {
            await stripe.refunds.create({ payment_intent: paymentIntent.id });

            await Order.findByIdAndUpdate(orderId, { paymentStatus: "failed", status: "cancelled" });
        } catch (refundErr) {
            console.error("Refund failed:", refundErr);
        }

        return sendResponse(res, status.INTERNAL_SERVER_ERROR, err.message || "Webhook processing failed", null, { received: true });
    } finally {
        session.endSession();
    }
});