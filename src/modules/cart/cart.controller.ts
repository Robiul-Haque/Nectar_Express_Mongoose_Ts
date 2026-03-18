import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import Cart from "./cart.model";
import Product from "../product/product.model";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

export const updateCartItems = catchAsync(async (req: Request, res: Response) => {
    const userId = req.user!.sub;
    const { add = [], update = [], remove = [] } = req.body;

    let cart = await Cart.findOne({ user: userId });
    if (!cart) cart = await Cart.create({ user: userId, items: [] });

    const productIds = [...add.map((i: any) => i.productId), ...update.map((i: any) => i.productId)];
    const products = await Product.find({ _id: { $in: productIds }, isActive: true }).select("price discountPrice stock").lean();
    const productMap = new Map(products.map((p) => [p._id.toString(), p]));

    // ADD ITEMS
    for (const item of add) {
        const product = productMap.get(item.productId);

        if (!product) continue;

        const finalPrice = product.discountPrice ?? product.price;

        const exist = cart.items.find((i) => i.product.toString() === item.productId);
        if (exist) {
            const newQty = exist.quantity + item.quantity;
            if (product.stock < newQty) continue;
            exist.quantity = newQty;
        } else {
            if (product.stock < item.quantity) continue;

            cart.items.push({ product: item.productId, quantity: item.quantity, price: finalPrice });
        }
    }

    // UPDATE ITEMS
    for (const item of update) {
        const product = productMap.get(item.productId);
        if (!product) continue;

        const cartItem = cart.items.find((i) => i.product.toString() === item.productId);
        if (!cartItem) continue;

        if (product.stock < item.quantity) continue;

        cartItem.quantity = item.quantity;
    }

    // REMOVE ITEMS
    if (remove.length) cart.items = cart.items.filter((item) => !remove.includes(item.product.toString()));

    // RECALCULATE CART
    cart.totalQuantity = cart.items.reduce((sum, i) => sum + i.quantity, 0);
    cart.totalPrice = cart.items.reduce((sum, i) => sum + i.quantity * i.price, 0);

    await cart.save();

    return sendResponse(res, status.OK, "Cart updated successfully", null, cart);
});

export const getAllCarts = catchAsync(async (req: Request, res: Response) => {
    const page = Number(req.query.page) || 1;
    const limit = Number(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const carts = await Cart.find().populate("user", "name email image").populate("items.product", "name price discountPrice image").sort({ updatedAt: -1 }).skip(skip).limit(limit).lean();
    const total = await Cart.countDocuments();

    return sendResponse(res, status.OK, "Carts retrieved successfully", { total, page, limit, totalPages: Math.ceil(total / limit) }, carts);
});

export const adminUpdateCartItem = catchAsync(async (req: Request, res: Response) => {
    const { id: cartId } = req.params;
    const { productId, action } = req.body;

    const cart = await Cart.findById(cartId);
    if (!cart) return sendResponse(res, 404, "Cart not found");

    const item = cart.items.find((i) => i.product.toString() === productId);
    if (!item) return sendResponse(res, 404, "Item not found in cart");

    if (action === "increment") {
        item.quantity += 1;
    } else if (action === "decrement") {
        item.quantity -= 1;
        if (item.quantity <= 0) cart.items = cart.items.filter((i) => i.product.toString() !== productId);
    } else if (action === "remove") {
        cart.items = cart.items.filter((i) => i.product.toString() !== productId);
    }

    cart.totalQuantity = cart.items.reduce((sum, i) => sum + i.quantity, 0);
    cart.totalPrice = cart.items.reduce((sum, i) => sum + i.quantity * i.price, 0);

    await cart.save();

    return sendResponse(res, status.OK, "Cart updated successfully", null, cart);
});