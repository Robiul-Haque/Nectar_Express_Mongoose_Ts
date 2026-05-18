import { Request, Response } from "express";
import stripe from "../../config/stripe.config";
import { env } from "../../config/env";
import mongoose from "mongoose";
import Cart from "../cart/cart.model";
import Order from "../order/order.model";
import Product from "../product/product.model";

export const stripeWebhookWithOrderComplete = async (req: Request, res: Response) => {
    const sig = req.headers["stripe-signature"] as string;

    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, env.STRIPE_WEBHOOK_SECRET);
    } catch (err: any) {
        console.error("❌ Invalid webhook signature:", err.message);
        return res.status(400).json({ received: false });
    }

    // Only payment success event
    if (event.type !== "payment_intent.succeeded") return res.status(200).json({ received: true });

    const paymentIntent: any = event.data.object;
    const orderId = paymentIntent?.metadata?.orderId;

    if (!orderId) {
        console.error("❌ Missing orderId in metadata");
        return res.status(200).json({ received: true });
    }

    const session = await mongoose.startSession();

    try {
        await session.withTransaction(async () => {
            const order = await Order.findById(orderId).session(session);
            if (!order) throw new Error("Order not found");
            if (order.paymentStatus === "paid") return;

            // Fetch products once
            const productIds = order.items.map(i => i.product);
            const products = await Product.find({ _id: { $in: productIds } }).select("stock").session(session);
            const stockMap = new Map(products.map(p => [p._id.toString(), p.stock]));

            // STOCK CHECK + UPDATE
            for (const item of order.items) {
                const stock = stockMap.get(item.product.toString());
                if (stock === undefined) throw new Error("Product not found");
                if (stock < item.quantity) throw new Error(`Insufficient stock for ${item.name}`);

                const updated = await Product.updateOne({ _id: item.product, stock: { $gte: item.quantity } }, { $inc: { stock: -item.quantity } }, { session });
                if (updated.modifiedCount === 0) throw new Error("Stock race condition");
            }

            // UPDATE ORDER
            order.paymentStatus = "paid";
            order.status = "pending";
            order.paymentIntentId = paymentIntent.id;

            await order.save({ session });
            await Cart.deleteOne({ user: order.user }).session(session);

            // SOCKET EMIT
            const io = req.app.get("io");
            if (io) io.to(order.user.toString()).emit("payment-success", { orderId: order._id, paymentIntentId: paymentIntent.id, message: "Payment completed successfully" });

            console.log("✅ Order completed:", order._id);
        });
        return res.status(200).json({ received: true });
    } catch (error: any) {
        console.error("❌ Webhook error:", error.message);
        // Refund safe fallback
        try {
            await stripe.refunds.create({ payment_intent: paymentIntent.id });
            await Order.findByIdAndUpdate(orderId, { paymentStatus: "failed", status: "cancelled" });
        } catch (refundErr) {
            console.error("❌ Refund failed:", refundErr);
        }
        return res.status(200).json({ received: true });
    } finally {
        session.endSession();
    }
};