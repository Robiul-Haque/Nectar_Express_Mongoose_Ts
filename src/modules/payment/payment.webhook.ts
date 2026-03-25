import { Request, Response } from "express";
import stripe from "../../config/stripe.config";
import { env } from "../../config/env";
import mongoose from "mongoose";
import Cart from "../cart/cart.model";
import Order from "../order/order.model";
import Product from "../product/product.model";

export const stripeWebhook = async (req: Request, res: Response) => {
    const sig = req.headers["stripe-signature"] as string;

    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err: any) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // 🎯 SUCCESS PAYMENT
    if (event.type === "payment_intent.succeeded") {
        const paymentIntent: any = event.data.object;

        const { userId, cartId } = paymentIntent.metadata;

        const session = await mongoose.startSession();

        try {
            session.startTransaction();

            // 🔍 Get cart
            const cart = await Cart.findById(cartId)
                .populate("items.product", "name image stock isActive price discountPrice")
                .session(session);

            if (!cart || cart.items.length === 0) {
                throw new Error("Cart not found or empty");
            }

            const orderItems: any[] = [];

            for (const item of cart.items) {
                const product: any = item.product;

                if (!product) throw new Error("Product not found");

                if (!product.isActive) {
                    throw new Error(`${product.name} is inactive`);
                }

                if (product.stock < item.quantity) {
                    throw new Error(`Stock issue for ${product.name}`);
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

            const totalPrice = orderItems.reduce(
                (sum, i) => sum + i.price * i.quantity,
                0
            );

            // ✅ CREATE ORDER
            const [order] = await Order.create(
                [
                    {
                        user: userId,
                        items: orderItems,
                        totalQuantity: cart.totalQuantity,
                        totalPrice,
                        shippingAddress: {}, // 👉 চাইলে metadata তে add করতে পারো
                        status: "confirmed"
                    }
                ],
                { session }
            );

            // 🔥 STOCK UPDATE
            for (const item of orderItems) {
                const updated = await Product.updateOne(
                    {
                        _id: item.product,
                        stock: { $gte: item.quantity }
                    },
                    {
                        $inc: { stock: -item.quantity }
                    },
                    { session }
                );

                if (updated.modifiedCount === 0) {
                    throw new Error("Stock conflict");
                }
            }

            // 🧹 CLEAR CART
            await Cart.deleteOne({ _id: cartId }).session(session);

            await session.commitTransaction();
        } catch (error) {
            await session.abortTransaction();
            console.error("Webhook error:", error);
        } finally {
            session.endSession();
        }
    }

    return res.json({ received: true });
};