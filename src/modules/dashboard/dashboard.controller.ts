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

    /*
    |--------------------------------------------------------------------------
    | DATE RANGES
    |--------------------------------------------------------------------------
    */

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);

    const weeklyStart = new Date();
    weeklyStart.setDate(now.getDate() - 6);
    weeklyStart.setHours(0, 0, 0, 0);

    const monthlyStart = new Date();
    monthlyStart.setDate(now.getDate() - 29);
    monthlyStart.setHours(0, 0, 0, 0);

    /*
    |--------------------------------------------------------------------------
    | PARALLEL DB OPERATIONS
    |--------------------------------------------------------------------------
    */

    const [
        totalSalesResult,
        dailyOrders,
        newCustomers,
        outOfStock,
        weeklySales,
        monthlySales,
        popularProducts,
    ] = await Promise.all([

        /*
        |--------------------------------------------------------------------------
        | TOTAL SALES
        |--------------------------------------------------------------------------
        */

        Order.aggregate([
            {
                $match: {
                    status: { $ne: "cancelled" },
                    paymentStatus: "paid",
                },
            },
            {
                $group: {
                    _id: null,
                    total: {
                        $sum: "$totalPrice",
                    },
                },
            },
        ]),

        /*
        |--------------------------------------------------------------------------
        | TODAY ORDERS
        |--------------------------------------------------------------------------
        */

        Order.countDocuments({
            createdAt: {
                $gte: todayStart,
            },
            status: {
                $ne: "cancelled",
            },
        }),

        /*
        |--------------------------------------------------------------------------
        | NEW CUSTOMERS (LAST 30 DAYS)
        |--------------------------------------------------------------------------
        */

        User.countDocuments({
            role: "user",
            createdAt: {
                $gte: monthlyStart,
            },
        }),

        /*
        |--------------------------------------------------------------------------
        | OUT OF STOCK
        |--------------------------------------------------------------------------
        */

        Product.countDocuments({
            stock: {
                $lte: 0,
            },
            isActive: true,
        }),

        /*
        |--------------------------------------------------------------------------
        | WEEKLY SALES OVERVIEW
        |--------------------------------------------------------------------------
        */

        Order.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: weeklyStart,
                    },
                    status: {
                        $ne: "cancelled",
                    },
                    paymentStatus: "paid",
                },
            },
            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: "%a",
                            date: "$createdAt",
                        },
                    },
                    revenue: {
                        $sum: "$totalPrice",
                    },
                    orders: {
                        $sum: 1,
                    },
                },
            },
            {
                $sort: {
                    _id: 1,
                },
            },
        ]),

        /*
        |--------------------------------------------------------------------------
        | MONTHLY SALES OVERVIEW
        |--------------------------------------------------------------------------
        */

        Order.aggregate([
            {
                $match: {
                    createdAt: {
                        $gte: monthlyStart,
                    },
                    status: {
                        $ne: "cancelled",
                    },
                    paymentStatus: "paid",
                },
            },
            {
                $group: {
                    _id: {
                        $dateToString: {
                            format: "%Y-%m-%d",
                            date: "$createdAt",
                        },
                    },
                    revenue: {
                        $sum: "$totalPrice",
                    },
                    orders: {
                        $sum: 1,
                    },
                },
            },
            {
                $sort: {
                    _id: 1,
                },
            },
        ]),

        /*
        |--------------------------------------------------------------------------
        | POPULAR PRODUCTS
        |--------------------------------------------------------------------------
        */

        Order.aggregate([

            {
                $match: {
                    status: { $ne: "cancelled" },
                },
            },

            {
                $unwind: "$products",
            },

            {
                $group: {
                    _id: "$products.product",

                    totalSold: {
                        $sum: "$products.quantity",
                    },
                },
            },

            {
                $sort: {
                    totalSold: -1,
                },
            },

            {
                $limit: 4,
            },

            {
                $lookup: {
                    from: "products",
                    localField: "_id",
                    foreignField: "_id",
                    as: "product",
                },
            },

            {
                $unwind: "$product",
            },

            {
                $project: {
                    _id: 0,

                    productId: "$product._id",

                    name: "$product.name",

                    slug: "$product.slug",

                    image: {
                        $arrayElemAt: [
                            "$product.images.url",
                            0,
                        ],
                    },

                    price: "$product.price",

                    totalSold: 1,
                },
            },
        ]),
    ]);

    /*
    |--------------------------------------------------------------------------
    | FINAL RESPONSE
    |--------------------------------------------------------------------------
    */

    const responseData = {

        cards: {
            totalSales:
                totalSalesResult?.[0]?.total || 0,

            dailyOrders,

            newCustomers,

            outOfStock,
        },

        salesOverview: {
            weekly: weeklySales,
            monthly: monthlySales,
        },

        popularProducts,
    };

    return sendResponse(
        res,
        status.OK,
        "Dashboard analytics retrieved successfully",
        null,
        responseData
    );
}
);