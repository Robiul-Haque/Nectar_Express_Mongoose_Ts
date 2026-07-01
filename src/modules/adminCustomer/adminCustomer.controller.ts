import { Request, Response } from "express";
import mongoose, { Types } from "mongoose";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import status from "http-status";
import User from "../user/user.model";
import Order from "../order/order.model";
import Cart from "../cart/cart.model";
import Bookmark from "../bookmark/bookmark.model";
import Chat from "../chat/chat.model";
import Message from "../message/message.model";
import LoginHistory from "./loginHistory.model";
import AdminNote from "./adminNote.model";
import redis from "../../utils/redis";

// ─── Helper ───────────────────────────────────────────────────────────────────

/**
 * Validates that the target user exists and is a customer (not admin/driver).
 * Returns the user document or null.
 */
const getCustomerOrFail = async (res: Response, userId: string) => {
    if (!mongoose.Types.ObjectId.isValid(userId)) {
        sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");
        return null;
    }
    const user = await User.findOne({ _id: userId, role: "user" })
        .select("name email provider role isActive isVerified avatar location notificationEnabled createdAt updatedAt lastLoginAt failedLoginCount loginLockedUntil passwordChangedAt appVersion device")
        .lean();

    if (!user) {
        sendResponse(res, status.NOT_FOUND, "Customer not found");
        return null;
    }
    return user;
};

// ─── 1. CUSTOMER FULL DETAILS ─────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id
 * Returns a comprehensive customer overview including:
 * - Basic profile, verification, status
 * - Security info (lock state, password change, failed logins)
 * - Device list
 * - Joined date, last seen, last known IP (if available)
 */
export const getCustomerDetails = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const user = await User.findOne({ _id: id, role: "user" })
        .select("+lastKnownIp name email provider role isActive isVerified avatar location notificationEnabled createdAt updatedAt lastLoginAt failedLoginCount loginLockedUntil passwordChangedAt appVersion device")
        .lean();

    if (!user) return sendResponse(res, status.NOT_FOUND, "Customer not found");

    const now = new Date();
    const isLocked = !!(user.loginLockedUntil && user.loginLockedUntil > now);
    const lockRemainingMs = isLocked ? (user as any).loginLockedUntil!.getTime() - now.getTime() : 0;

    // Check Redis for cached lock state
    let redisLockUntil: string | null = null;
    if (redis) {
        try {
            redisLockUntil = await redis.get(`auth:lock:${user.email.toLowerCase()}`);
        } catch (_) { /* non-critical */ }
    }

    const responseData = {
        // ── Profile ──────────────────────────────────────────────────────────
        profile: {
            id: (user as any)._id,
            name: user.name,
            email: user.email,
            avatar: user.avatar?.url || null,
            provider: user.provider,
            role: user.role,
            notificationEnabled: user.notificationEnabled,
            appVersion: user.appVersion || null,
            location: user.location || null,
            joinedAt: (user as any).createdAt,
            updatedAt: (user as any).updatedAt
        },
        // ── Status ────────────────────────────────────────────────────────────
        status: {
            isActive: user.isActive,
            isVerified: user.isVerified,
            lastLoginAt: user.lastLoginAt || null,
            lastKnownIp: (user as any).lastKnownIp || null
        },
        // ── Security ─────────────────────────────────────────────────────────
        security: {
            isLocked,
            loginLockedUntil: user.loginLockedUntil || null,
            lockRemainingMs: isLocked ? lockRemainingMs : 0,
            failedLoginCount: user.failedLoginCount || 0,
            passwordChangedAt: user.passwordChangedAt || null,
            redisLockActive: !!redisLockUntil
        },
        // ── Devices ───────────────────────────────────────────────────────────
        devices: (user.device || []).map((d: any) => ({
            platform: d.platform,
            deviceId: d.deviceId || null,
            deviceModel: d.deviceModel || null,
            osVersion: d.osVersion || null,
            appVersion: d.appVersion || null,
            lastActive: d.lastActive || null
        }))
    };

    return sendResponse(res, status.OK, "Customer details retrieved successfully", null, responseData);
});

// ─── 2. ORDER SUMMARY ─────────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/orders
 * Returns paginated orders + an aggregated order summary.
 */
export const getCustomerOrderSummary = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 10, 50);
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const userId = new Types.ObjectId(id);

    // Run summary aggregation + paginated orders in parallel
    const [summaryResult, orders, total] = await Promise.all([
        Order.aggregate([
            { $match: { user: userId } },
            {
                $group: {
                    _id: null,
                    totalOrders: { $sum: 1 },
                    totalSpent: {
                        $sum: {
                            $cond: [{ $eq: ["$paymentStatus", "paid"] }, "$totalPrice", 0]
                        }
                    },
                    deliveredCount: {
                        $sum: { $cond: [{ $eq: ["$orderStatus", "delivered"] }, 1, 0] }
                    },
                    cancelledCount: {
                        $sum: { $cond: [{ $eq: ["$orderStatus", "cancelled"] }, 1, 0] }
                    },
                    pendingCount: {
                        $sum: { $cond: [{ $eq: ["$orderStatus", "pending"] }, 1, 0] }
                    },
                    confirmedCount: {
                        $sum: { $cond: [{ $eq: ["$orderStatus", "confirmed"] }, 1, 0] }
                    },
                    shippedCount: {
                        $sum: { $cond: [{ $eq: ["$orderStatus", "shipped"] }, 1, 0] }
                    },
                    paidOrders: {
                        $sum: { $cond: [{ $eq: ["$paymentStatus", "paid"] }, 1, 0] }
                    },
                    failedPaymentOrders: {
                        $sum: { $cond: [{ $eq: ["$paymentStatus", "failed"] }, 1, 0] }
                    },
                    avgOrderValue: { $avg: "$totalPrice" }
                }
            }
        ]),
        Order.find({ user: userId })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .select("orderStatus paymentStatus totalPrice totalQuantity items shippingAddress createdAt paymentIntentId")
            .lean(),
        Order.countDocuments({ user: userId })
    ]);

    const summary = summaryResult[0] || {
        totalOrders: 0, totalSpent: 0, deliveredCount: 0, cancelledCount: 0,
        pendingCount: 0, confirmedCount: 0, shippedCount: 0, paidOrders: 0,
        failedPaymentOrders: 0, avgOrderValue: 0
    };

    const pagination = { total, page, limit, totalPages: Math.ceil(total / limit) };

    return sendResponse(res, status.OK, "Customer order summary retrieved", pagination, {
        summary: {
            totalOrders: summary.totalOrders,
            totalSpent: parseFloat(summary.totalSpent?.toFixed(2) || "0"),
            avgOrderValue: parseFloat(summary.avgOrderValue?.toFixed(2) || "0"),
            byStatus: {
                pending: summary.pendingCount,
                confirmed: summary.confirmedCount,
                shipped: summary.shippedCount,
                delivered: summary.deliveredCount,
                cancelled: summary.cancelledCount
            },
            byPayment: {
                paid: summary.paidOrders,
                failed: summary.failedPaymentOrders
            }
        },
        orders
    });
});

// ─── 3. ACTIVITY TIMELINE ─────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/timeline
 * Returns a unified, chronologically-sorted activity timeline combining:
 * login events, orders, and bookmarks.
 */
export const getCustomerActivityTimeline = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 50);
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const userId = new Types.ObjectId(id);

    // Fetch multiple event sources in parallel
    const [loginEvents, recentOrders, recentBookmarks] = await Promise.all([
        LoginHistory.find({ userId })
            .sort({ createdAt: -1 })
            .limit(50)
            .select("event provider ip platform appVersion createdAt")
            .lean(),
        Order.find({ user: userId })
            .sort({ createdAt: -1 })
            .limit(30)
            .select("orderStatus paymentStatus totalPrice createdAt")
            .lean(),
        Bookmark.find({ user: userId })
            .sort({ createdAt: -1 })
            .limit(20)
            .populate("product", "name image")
            .select("product createdAt")
            .lean()
    ]);

    // Normalize into unified timeline events
    const events: Array<{ type: string; description: string; meta: unknown; timestamp: Date }> = [];

    for (const e of loginEvents) {
        const descriptions: Record<string, string> = {
            login_success: "Successful login",
            login_failed: "Failed login attempt",
            account_locked: "Account locked due to multiple failed attempts",
            account_unlocked: "Account unlocked by admin",
            password_changed: "Password changed",
            otp_verified: "Email OTP verified",
            logout: "Logged out"
        };
        events.push({
            type: "auth",
            description: descriptions[e.event] || e.event,
            meta: { event: e.event, provider: e.provider, platform: e.platform, ip: e.ip },
            timestamp: (e as any).createdAt
        });
    }

    for (const o of recentOrders) {
        events.push({
            type: "order",
            description: `Order ${o.orderStatus} — $${o.totalPrice}`,
            meta: { orderId: (o as any)._id, orderStatus: o.orderStatus, paymentStatus: o.paymentStatus, totalPrice: o.totalPrice },
            timestamp: (o as any).createdAt
        });
    }

    for (const b of recentBookmarks) {
        const product: any = b.product;
        events.push({
            type: "wishlist",
            description: `Added "${product?.name || "product"}" to wishlist`,
            meta: { productId: product?._id, productName: product?.name, productImage: product?.image?.url || null },
            timestamp: (b as any).createdAt
        });
    }

    // Sort all events by timestamp descending
    events.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const total = events.length;
    const paginated = events.slice(skip, skip + limit);

    return sendResponse(res, status.OK, "Customer activity timeline retrieved", {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
    }, paginated);
});

// ─── 4. LOGIN HISTORY ─────────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/login-history
 * Returns paginated security/login event history for the customer.
 */
export const getCustomerLoginHistory = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const [history, total] = await Promise.all([
        LoginHistory.find({ userId: id })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .select("event provider ip userAgent platform deviceId appVersion meta createdAt")
            .lean(),
        LoginHistory.countDocuments({ userId: id })
    ]);

    return sendResponse(res, status.OK, "Login history retrieved", {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
    }, history);
});

// ─── 5. CHAT SUMMARY ──────────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/chat-summary
 * Returns support chat summary: total chats, last message, unread count.
 */
export const getCustomerChatSummary = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const userId = new Types.ObjectId(id);

    // Get all chats the customer participated in
    const chats = await Chat.find({ participants: userId })
        .sort({ lastUpdated: -1 })
        .select("participants lastMessage lastUpdated createdAt")
        .populate({ path: "participants", select: "name email role avatar" })
        .lean();

    const totalChats = chats.length;

    // Count unread messages across all chats (messages not read by this user)
    const chatIds = chats.map((c: any) => c._id);

    const [unreadCount, totalMessages] = await Promise.all([
        chatIds.length > 0
            ? Message.countDocuments({ chatId: { $in: chatIds }, readBy: { $ne: userId } })
            : Promise.resolve(0),
        chatIds.length > 0
            ? Message.countDocuments({ chatId: { $in: chatIds } })
            : Promise.resolve(0)
    ]);

    const lastChat = chats[0] || null;
    const lastMessage = lastChat
        ? { content: lastChat.lastMessage, sentAt: (lastChat as any).lastUpdated }
        : null;

    // Format chats with other participant info (exclude self)
    const formattedChats = chats.slice(0, 10).map((chat: any) => ({
        chatId: chat._id,
        lastMessage: chat.lastMessage || null,
        lastUpdated: chat.lastUpdated,
        otherParticipant: chat.participants
            .filter((p: any) => p._id.toString() !== id)
            .map((p: any) => ({
                id: p._id,
                name: p.name,
                email: p.email,
                role: p.role,
                avatar: p.avatar?.url || null
            }))[0] || null
    }));

    return sendResponse(res, status.OK, "Customer chat summary retrieved", null, {
        summary: {
            totalChats,
            totalMessages,
            unreadMessages: unreadCount,
            lastMessage
        },
        recentChats: formattedChats
    });
});

// ─── 6. WISHLIST & CART SUMMARY ───────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/wishlist-cart
 * Returns wishlist (bookmarks) and cart summary.
 */
export const getCustomerWishlistCart = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const [wishlistItems, cart] = await Promise.all([
        Bookmark.find({ user: id })
            .sort({ createdAt: -1 })
            .limit(20)
            .populate("product", "name image price discountPrice stock isActive")
            .lean(),
        Cart.findOne({ user: id })
            .populate("items.product", "name image price discountPrice stock")
            .lean()
    ]);

    const formattedWishlist = wishlistItems.map((b: any) => {
        const p = b.product;
        return {
            productId: p?._id || null,
            name: p?.name || null,
            image: p?.image?.url || null,
            price: p?.price || 0,
            discountPrice: p?.discountPrice || null,
            stock: p?.stock || 0,
            isActive: p?.isActive ?? false,
            addedAt: b.createdAt
        };
    });

    const formattedCartItems = (cart?.items || []).map((item: any) => {
        const p = item.product;
        return {
            productId: p?._id || item.product,
            name: p?.name || null,
            image: p?.image?.url || null,
            price: item.price,
            quantity: item.quantity,
            variant: item.variant || null,
            subtotal: item.price * item.quantity
        };
    });

    return sendResponse(res, status.OK, "Wishlist & cart summary retrieved", null, {
        wishlist: {
            count: wishlistItems.length,
            items: formattedWishlist
        },
        cart: cart
            ? {
                totalItems: cart.totalQuantity,
                totalPrice: cart.totalPrice,
                itemCount: (cart.items || []).length,
                items: formattedCartItems,
                lastUpdated: (cart as any).updatedAt
            }
            : null
    });
});

// ─── 7. PAYMENT SUMMARY ───────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/payment-summary
 * Returns aggregated payment statistics for the customer.
 */
export const getCustomerPaymentSummary = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const userId = new Types.ObjectId(id);

    const [paymentStats, recentPaidOrders] = await Promise.all([
        Order.aggregate([
            { $match: { user: userId } },
            {
                $group: {
                    _id: "$paymentStatus",
                    count: { $sum: 1 },
                    totalAmount: { $sum: "$totalPrice" }
                }
            }
        ]),
        Order.find({ user: userId, paymentStatus: "paid" })
            .sort({ createdAt: -1 })
            .limit(5)
            .select("totalPrice paymentIntentId orderStatus createdAt")
            .lean()
    ]);

    // Normalize payment stats
    const statsMap: Record<string, { count: number; totalAmount: number }> = {};
    for (const s of paymentStats) {
        statsMap[s._id] = { count: s.count, totalAmount: s.totalAmount };
    }

    const totalPaid = statsMap["paid"]?.totalAmount || 0;
    const totalPaidOrders = statsMap["paid"]?.count || 0;
    const totalFailedOrders = statsMap["failed"]?.count || 0;
    const totalPendingOrders = statsMap["pending"]?.count || 0;

    return sendResponse(res, status.OK, "Customer payment summary retrieved", null, {
        summary: {
            lifetimeSpending: parseFloat(totalPaid.toFixed(2)),
            paidOrdersCount: totalPaidOrders,
            failedPaymentsCount: totalFailedOrders,
            pendingPaymentsCount: totalPendingOrders,
            avgTransactionValue: totalPaidOrders > 0 ? parseFloat((totalPaid / totalPaidOrders).toFixed(2)) : 0
        },
        recentPaidOrders
    });
});

// ─── 8. ADMIN NOTES — CRUD ────────────────────────────────────────────────────

/**
 * GET /api/v1/admin/customers/:id/notes
 * Returns all admin notes for this customer (paginated).
 */
export const getAdminNotes = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const page = Math.max(parseInt(req.query.page as string) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit as string) || 20, 100);
    const skip = (page - 1) * limit;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const [notes, total] = await Promise.all([
        AdminNote.find({ userId: id })
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .populate("adminId", "name email avatar")
            .lean(),
        AdminNote.countDocuments({ userId: id })
    ]);

    const formatted = notes.map((n: any) => ({
        _id: n._id,
        note: n.note,
        createdAt: n.createdAt,
        updatedAt: n.updatedAt,
        adminId: {
            _id: n.adminId?._id,
            name: n.adminId?.name,
            email: n.adminId?.email,
            avatar: n.adminId?.avatar?.url || null
        }
    }));

    return sendResponse(res, status.OK, "Admin notes retrieved", {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
    }, formatted);
});

/**
 * POST /api/v1/admin/customers/:id/notes
 * Adds a new internal note for this customer.
 */
export const addAdminNote = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const adminId = new Types.ObjectId(req.user!.sub);
    const { note } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    // Verify customer exists
    const customer = await User.findOne({ _id: id, role: "user" }).select("_id name").lean();
    if (!customer) return sendResponse(res, status.NOT_FOUND, "Customer not found");

    const created = await AdminNote.create({ userId: id, adminId, note });

    return sendResponse(res, status.CREATED, "Note added successfully", null, {
        noteId: created._id,
        note: created.note,
        userId: created.userId,
        adminId: created.adminId,
        createdAt: created.createdAt
    });
});

/**
 * PUT /api/v1/admin/customers/:id/notes/:noteId
 * Updates an existing admin note.
 */
export const updateAdminNote = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const noteId = req.params.noteId as string;
    // Cast to ObjectId so Mongoose can properly match the stored ObjectId field
    const adminId = new Types.ObjectId(req.user!.sub);
    const { note } = req.body;

    if (!mongoose.Types.ObjectId.isValid(id) || !mongoose.Types.ObjectId.isValid(noteId)) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid ID");
    }

    // Only the admin who created the note can update it
    const updated = await AdminNote.findOneAndUpdate(
        { _id: noteId, userId: id, adminId },
        { $set: { note } },
        { new: true, runValidators: true }
    ).lean();

    if (!updated) return sendResponse(res, status.NOT_FOUND, "Note not found or you don't have permission to edit it");

    return sendResponse(res, status.OK, "Note updated successfully", null, updated);
});

/**
 * DELETE /api/v1/admin/customers/:id/notes/:noteId
 * Deletes an admin note. Any admin can delete any note (for moderation).
 */
export const deleteAdminNote = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;
    const noteId = req.params.noteId as string;

    if (!mongoose.Types.ObjectId.isValid(id) || !mongoose.Types.ObjectId.isValid(noteId)) {
        return sendResponse(res, status.BAD_REQUEST, "Invalid ID");
    }

    const deleted = await AdminNote.findOneAndDelete({ _id: noteId, userId: id });
    if (!deleted) return sendResponse(res, status.NOT_FOUND, "Note not found");

    return sendResponse(res, status.OK, "Note deleted successfully");
});

// ─── 9. UNBLOCK CUSTOMER ─────────────────────────────────────────────────────

/**
 * POST /api/v1/admin/customers/:id/unblock
 * Admin manually unlocks a brute-force locked account.
 * Also resets failedLoginCount and clears Redis cache.
 */
export const unblockCustomer = catchAsync(async (req: Request, res: Response) => {
    const id = req.params.id as string;

    if (!mongoose.Types.ObjectId.isValid(id)) return sendResponse(res, status.BAD_REQUEST, "Invalid customer ID");

    const user = await User.findById(id).select("email loginLockedUntil failedLoginCount isActive role");
    if (!user) return sendResponse(res, status.NOT_FOUND, "User not found");
    if (user.role === "admin") return sendResponse(res, status.FORBIDDEN, "Cannot unblock an admin account via this endpoint");

    user.loginLockedUntil = null;
    user.failedLoginCount = 0;
    await user.save();

    // Clear Redis lock cache
    if (redis) {
        try {
            await redis.del(`auth:lock:${user.email.toLowerCase()}`);
        } catch (_) { /* non-critical */ }
    }

    // Record unlock event
    LoginHistory.create({
        userId: id,
        event: "account_unlocked",
        provider: user.provider,
        ip: "admin_action",
        userAgent: `Admin: ${req.user!.sub}`,
        platform: "unknown",
        meta: { unlockedBy: req.user!.sub }
    }).catch(() => { /* non-critical */ });

    return sendResponse(res, status.OK, "Account unlocked successfully", null, {
        userId: id,
        email: user.email,
        unlockedAt: new Date()
    });
});
