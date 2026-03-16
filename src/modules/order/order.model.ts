import { Schema, model, Types } from "mongoose";

const orderItemSchema = new Schema(
    {
        product: {
            type: Types.ObjectId,
            ref: "Product",
            required: true
        },

        name: {
            type: String,
            required: true
        },

        image: {
            type: String,
            required: true
        },

        price: {
            type: Number,
            required: true
        },

        quantity: {
            type: Number,
            required: true,
            min: 1
        }

    },
    { _id: false }
);

const orderSchema = new Schema(
    {
        user: {
            type: Types.ObjectId,
            ref: "User",
            required: true,
            index: true
        },

        items: {
            type: [orderItemSchema],
            required: true
        },

        totalQuantity: {
            type: Number,
            required: true
        },

        totalPrice: {
            type: Number,
            required: true
        },

        shippingAddress: {
            address: String,
            city: String,
            country: String,
            phone: String
        },

        status: {
            type: String,
            enum: ["pending", "confirmed", "shipped", "delivered", "cancelled"],
            default: "pending",
            index: true
        }

    },
    {
        timestamps: true,
        versionKey: false
    }
);

orderSchema.index({ user: 1, createdAt: -1 });

const Order = model("Order", orderSchema);
export default Order;