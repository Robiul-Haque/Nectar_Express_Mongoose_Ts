import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import Order from "../order/order.model";
import User from "../user/user.model";
import Product from "../product/product.model";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

export const getSalesOverview = catchAsync(async (req: Request, res: Response) => {
    const { range = "weekly" } = req.query;
    const now = new Date();
    let startDate: Date;
    let groupBy: any;

    if (range === "weekly") {
        // Last 7 days
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
        startDate.setHours(0, 0, 0, 0);
        groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
    } else if (range === "monthly") {
        // Last 30 days
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 29);
        startDate.setHours(0, 0, 0, 0);
        groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
    } else if (range === "last6months") {
        // Last 6 months
        startDate = new Date(now.getFullYear(), now.getMonth() - 5, 1);
        startDate.setHours(0, 0, 0, 0);
        groupBy = { $dateToString: { format: "%Y-%m", date: "$createdAt" } };
    } else if (range === "yearly") {
        // Last 12 months
        startDate = new Date(now.getFullYear(), now.getMonth() - 11, 1);
        startDate.setHours(0, 0, 0, 0);
        groupBy = { $dateToString: { format: "%Y-%m", date: "$createdAt" } };
    } else {
        startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
        startDate.setHours(0, 0, 0, 0);
        groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
    }

    const salesData = await Order.aggregate([
        {
            $match: {
                createdAt: { $gte: startDate },
                status: { $ne: "cancelled" },
                paymentStatus: "paid"
            }
        },
        {
            $group: {
                _id: groupBy,
                totalSales: { $sum: "$totalPrice" },
                orderCount: { $sum: 1 }
            }
        },
        { $sort: { _id: 1 } }
    ]);

    return sendResponse(res, status.OK, "Sales overview retrieved successfully", null, salesData);
});

export const getDashboardStats = catchAsync(async (req: Request, res: Response) => {
    const totalOrders = await Order.countDocuments({ status: { $ne: "cancelled" } });
    const totalUsers = await User.countDocuments({ role: "user" });
    const totalProducts = await Product.countDocuments({ isActive: true });

    const totalSalesResult = await Order.aggregate([
        { $match: { status: { $ne: "cancelled" }, paymentStatus: "paid" } },
        { $group: { _id: null, total: { $sum: "$totalPrice" } } }
    ]);

    const stats = {
        totalOrders,
        totalUsers,
        totalProducts,
        totalSales: totalSalesResult.length > 0 ? totalSalesResult[0].total : 0,
    };

    return sendResponse(res, status.OK, "Dashboard stats retrieved successfully", null, stats);
});
