import { Request, Response } from "express";
import catchAsync from "../../utils/catchAsync";
import Order from "../order/order.model";
import User from "../user/user.model";
import Product from "../product/product.model";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";

// export const getSalesOverview = catchAsync(async (req: Request, res: Response) => {
//     const { range = "weekly" } = req.query;
//     const now = new Date();
//     let startDate: Date;
//     let groupBy: any;

//     if (range === "weekly") {
//         // Last 7 days
//         startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
//         startDate.setHours(0, 0, 0, 0);
//         groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
//     } else if (range === "monthly") {
//         // Last 30 days
//         startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 29);
//         startDate.setHours(0, 0, 0, 0);
//         groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
//     } else if (range === "last6months") {
//         // Last 6 months
//         startDate = new Date(now.getFullYear(), now.getMonth() - 5, 1);
//         startDate.setHours(0, 0, 0, 0);
//         groupBy = { $dateToString: { format: "%Y-%m", date: "$createdAt" } };
//     } else if (range === "yearly") {
//         // Last 12 months
//         startDate = new Date(now.getFullYear(), now.getMonth() - 11, 1);
//         startDate.setHours(0, 0, 0, 0);
//         groupBy = { $dateToString: { format: "%Y-%m", date: "$createdAt" } };
//     } else {
//         startDate = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
//         startDate.setHours(0, 0, 0, 0);
//         groupBy = { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } };
//     }

//     const salesData = await Order.aggregate([
//         {
//             $match: {
//                 createdAt: { $gte: startDate },
//                 status: { $ne: "cancelled" },
//                 paymentStatus: "paid"
//             }
//         },
//         {
//             $group: {
//                 _id: groupBy,
//                 totalSales: { $sum: "$totalPrice" },
//                 orderCount: { $sum: 1 }
//             }
//         },
//         { $sort: { _id: 1 } }
//     ]);

//     return sendResponse(res, status.OK, "Sales overview retrieved successfully", null, salesData);
// });

// export const getDashboardStats = catchAsync(async (req: Request, res: Response) => {
//     const totalOrders = await Order.countDocuments({ status: { $ne: "cancelled" } });
//     const newUsers = await User.countDocuments({ role: "user" });
//     const totalProducts = await Product.countDocuments({ isActive: true });

//     const totalSalesResult = await Order.aggregate([
//         { $match: { status: { $ne: "cancelled" }, paymentStatus: "paid" } },
//         { $group: { _id: null, total: { $sum: "$totalPrice" } } }
//     ]);

//     const stats = {
//         totalOrders,
//         newUsers,
//         totalProducts,
//         totalSales: totalSalesResult.length > 0 ? totalSalesResult[0].total : 0,
//     };

//     return sendResponse(res, status.OK, "Dashboard stats retrieved successfully", null, stats);
// });


export const getDashboardAnalytics = catchAsync(async (req: Request, res: Response) => {
    const now = new Date();

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const weeklyStart = new Date();
    weeklyStart.setDate(now.getDate() - 6);
    weeklyStart.setHours(0, 0, 0, 0);

    const monthlyStart = new Date();
    monthlyStart.setDate(now.getDate() - 29);
    monthlyStart.setHours(0, 0, 0, 0);


    const validOrderMatch = {
        paymentStatus: { $in: ["paid", "Paid", "PAID"] },
        status: { $nin: ["cancelled", "Cancelled"] }
    };

    const [totalSalesResult, dailyOrders, newCustomers, outOfStock, weeklySalesRaw, monthlySalesRaw, popularProducts] = await Promise.all([
        Order.aggregate([
            {
                $match: validOrderMatch
            },
            {
                $group: {
                    _id: null,
                    totalSales: { $sum: "$totalPrice" }
                }
            }
        ]),

        Order.countDocuments({
            createdAt: { $gte: todayStart },
            status: { $nin: ["cancelled", "Cancelled"] }
        }),

        User.countDocuments({
            role: "user",
            createdAt: { $gte: monthlyStart }
        }),

        Product.countDocuments({
            stock: {
                $lte: 0
            },
            isActive: true
        }),

        Order.aggregate([
            {
                $match: {
                    ...validOrderMatch,
                    createdAt: { $gte: weeklyStart }
                }
            },

            {
                $group: {
                    _id: {
                        $dayOfWeek: "$createdAt"
                    },
                    revenue: {
                        $sum: "$totalPrice"
                    },
                    orders: {
                        $sum: 1
                    }
                }
            },

            {
                $project: {
                    _id: 0,
                    dayNumber: "$_id",
                    day: { $arrayElemAt: [["", "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], "$_id"] },
                    revenue: 1,
                    orders: 1
                }
            },

            {
                $sort: {
                    dayNumber: 1
                }
            }
        ]),

        Order.aggregate([
            {
                $match: {
                    ...validOrderMatch,

                    createdAt: {
                        $gte: monthlyStart
                    }
                }
            },

            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: "%Y-%m-%d",
                            date: "$createdAt"
                        }
                    },

                    revenue: {
                        $sum: "$totalPrice"
                    },

                    orders: {
                        $sum: 1
                    }
                }
            },

            {
                $project: {
                    _id: 0,

                    date: "$_id",

                    revenue: 1,
                    orders: 1
                }
            },

            {
                $sort: {
                    date: 1
                }
            }
        ]),

        Order.aggregate([
            {
                $match: validOrderMatch
            },

            {
                $unwind: "$items"
            },

            {
                $group: {
                    _id: "$items.product",

                    totalSold: {
                        $sum: "$items.quantity"
                    }
                }
            },

            {
                $sort: {
                    totalSold: -1
                }
            },

            {
                $limit: 4
            },

            {
                $lookup: {
                    from: "products",
                    localField: "_id",
                    foreignField: "_id",
                    as: "product"
                }
            },

            {
                $unwind: "$product"
            },

            {
                $project: {
                    _id: 0,
                    productId: "$product._id",
                    name: "$product.name",
                    slug: "$product.slug",
                    image: "$product.image.url",
                    price: "$product.price",
                    stock: "$product.stock",
                    totalSold: 1
                }
            }
        ])
    ]);

    const responseData = {
        cards: {
            totalSales: totalSalesResult?.[0]?.totalSales || 0,
            dailyOrders,
            newCustomers,
            outOfStock
        },
        salesOverview: {
            weekly: weeklySalesRaw,
            monthly: monthlySalesRaw
        },
        popularProducts
    };

    return sendResponse(res, status.OK, "Dashboard analytics retrieved successfully", null, responseData);
}
);