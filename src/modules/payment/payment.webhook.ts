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
    const userId = paymentIntent?.metadata?.userId;
    const cartId = paymentIntent?.metadata?.cartId;
    const shippingAddress = paymentIntent?.metadata?.shippingAddress ? JSON.parse(paymentIntent.metadata.shippingAddress) : null;

    const session = await mongoose.startSession();

    try {
        await session.withTransaction(async () => {
            // 1. Check if order already exists by paymentIntentId or orderId
            let order = null;
            if (orderId) {
                order = await Order.findById(orderId).session(session);
            } else {
                order = await Order.findOne({ paymentIntentId: paymentIntent.id }).session(session);
            }

            // 2. If order exists and is already paid, just return
            if (order && order.paymentStatus === "paid") return;

            // 3. If order doesn't exist, create it from cart (User might have closed app before manual /order/create call)
            if (!order) {
                if (!userId || !cartId) {
                    console.error("❌ Missing userId or cartId in metadata for order creation");
                    return;
                }

                const cart = await Cart.findById(cartId).populate("items.product").session(session);
                if (!cart || cart.items.length === 0) {
                    console.error("❌ Cart not found or empty for webhook order creation");
                    return;
                }

                const orderItems: any[] = [];
                for (const item of cart.items) {
                    const product: any = item.product;
                    if (!product || !product.isActive || product.stock < item.quantity) {
                        throw new Error(`Stock issue for product: ${product?.name || item.product}`);
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

                [order] = await Order.create([{
                    user: userId,
                    items: orderItems,
                    totalQuantity: cart.totalQuantity,
                    totalPrice: orderItems.reduce((sum, i) => sum + i.price * i.quantity, 0),
                    shippingAddress,
                    paymentStatus: "paid",
                    paymentIntentId: paymentIntent.id,
                    status: "pending"
                }], { session });

                // STOCK UPDATE
                for (const item of orderItems) {
                    const updated = await Product.updateOne(
                        { _id: item.product, stock: { $gte: item.quantity } },
                        { $inc: { stock: -item.quantity } },
                        { session }
                    );
                    if (updated.modifiedCount === 0) throw new Error("Stock race condition during webhook");
                }

                await Cart.deleteOne({ _id: cartId }).session(session);
            } else {
                // 4. Update existing order (if it was created manually as pending)
                const productIds = order.items.map(i => i.product);
                const products = await Product.find({ _id: { $in: productIds } }).select("stock").session(session);
                const stockMap = new Map(products.map(p => [p._id.toString(), p.stock]));

                for (const item of order.items) {
                    const stock = stockMap.get(item.product.toString());
                    if (stock === undefined || stock < item.quantity) throw new Error(`Insufficient stock for ${item.name}`);

                    await Product.updateOne({ _id: item.product, stock: { $gte: item.quantity } }, { $inc: { stock: -item.quantity } }, { session });
                }

                order.paymentStatus = "paid";
                order.status = "pending";
                order.paymentIntentId = paymentIntent.id;
                await order.save({ session });
                await Cart.deleteOne({ user: order.user }).session(session);
            }

            // SOCKET EMIT (Optional notification)
            const io = req.app.get("io");
            if (io) io.to(order.user.toString()).emit("payment-success", { orderId: order._id, paymentIntentId: paymentIntent.id, message: "Payment completed successfully" });

            console.log("✅ Order processed via webhook:", order._id);
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