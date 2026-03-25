
import stripe from "../../config/stripe.config";
import Cart from "../cart/cart.model";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

export const createPaymentIntent = catchAsync(async (req, res) => {
    const userId = req.user!.sub;

    const cart = await Cart.findOne({ user: userId }).populate("items.product");
    if (!cart || cart.items.length === 0) return sendResponse(res, status.NOT_FOUND, "Cart is empty", null);

    let total = 0;

    for (const item of cart.items) {
        const product: any = item.product;
        if (!product || !product.isActive) return sendResponse(res, status.NOT_FOUND, "Invalid product", null);

        const price = product.discountPrice ?? product.price;
        total += price * item.quantity;
    }

    const paymentIntent = await stripe.paymentIntents.create({
        amount: total * 100,
        currency: "usd",
        metadata: { userId }
    });

    return sendResponse(res, status.OK, "Payment intent created", null, { clientSecret: paymentIntent.client_secret });
});