import mongoose, { Schema, Model } from "mongoose";
import { ICart, ICartItem } from "./cart.interface";

const cartItemSchema = new Schema<ICartItem>(
    {
        product: {
            type: Schema.Types.ObjectId,
            ref: "Product",
            required: [true, "Product is required"],
            index: true,
        },
        quantity: {
            type: Number,
            required: [true, "Quantity is required"],
            min: [1, "Quantity must be at least 1"],
            default: 1,
        },
        price: {
            type: Number,
            required: [true, "Price is required"],
            min: [0, "Price cannot be negative"],
        },
        variant: {
            type: String,
            trim: true,
        },
    },
    { _id: false }
);

const cartSchema = new Schema<ICart>(
    {
        user: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: [true, "User is required"],
            unique: true,
            index: true,
        },
        items: [cartItemSchema],
        totalPrice: {
            type: Number,
            required: true,
            default: 0,
            min: [0, "Total price cannot be negative"],
        },
        totalQuantity: {
            type: Number,
            required: true,
            default: 0,
            min: [0, "Total quantity cannot be negative"],
        },
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

cartSchema.pre("save", function () {
    this.totalQuantity = this.items.reduce((sum, item) => sum + item.quantity, 0);
    this.totalPrice = this.items.reduce((sum, item) => sum + item.quantity * item.price, 0);
});

cartSchema.index({ user: 1 });

const Cart: Model<ICart> = mongoose.model<ICart>("Cart", cartSchema);
export default Cart;