import stripe from "../../config/stripe.config";
import Cart from "../cart/cart.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import { Request, Response } from "express";

export const createPaymentIntent = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { shippingAddress } = req.body;

    const cart = await Cart.findOne({ user: userId }).populate("items.product").lean();
    if (!cart || cart.items.length === 0) return sendResponse(res, status.NOT_FOUND, "Cart is empty");

    let totalAmount = 0;

    for (const item of cart.items) {
        const product: any = item.product;

        if (!product || !product.isActive) return sendResponse(res, 400, "Invalid product in cart");
        if (product.stock < item.quantity) return sendResponse(res, 400, `Stock issue for ${product.name}`);

        const price = Math.round((product.discountPrice ?? product.price) * 100);
        totalAmount += price * item.quantity;
    }

    if (totalAmount <= 0) return sendResponse(res, 400, "Invalid cart total");

    const paymentIntent = await stripe.paymentIntents.create({
        amount: totalAmount,
        currency: "usd",
        automatic_payment_methods: {
            enabled: true,
            allow_redirects: "never",
        },
        metadata: {
            userId,
            cartId: cart._id.toString(),
            shippingAddress: JSON.stringify(shippingAddress),
        },
    });

    return sendResponse(res, status.OK, "Payment intent created", null, { clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id });
});