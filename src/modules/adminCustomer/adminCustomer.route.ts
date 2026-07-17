import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import {
    customerIdParamsSchema,
    addAdminNoteSchema,
    updateAdminNoteSchema,
    customerNoteParamsSchema,
    paginationQuerySchema
} from "./adminCustomer.validation";
import {
    getCustomerDetails,
    getCustomerOrderSummary,
    getCustomerActivityTimeline,
    getCustomerLoginHistory,
    getCustomerChatSummary,
    getCustomerWishlistCart,
    getCustomerPaymentSummary,
    getAdminNotes,
    addAdminNote,
    updateAdminNote,
    deleteAdminNote,
    unblockCustomer
} from "./adminCustomer.controller";

const router = Router();

// Secure all customer details/security routes for admin role only
router.use(authenticate(["admin"]));

// new api: Retrieves basic customer profile data, verification status, locations, and security metrics (failed login attempts, lock duration).
router.get("/:id", validateRequest(customerIdParamsSchema), getCustomerDetails);

// new api: Fetches lifetime e-commerce order metrics (total, completed, cancelled, pending counts) and a list of paginated orders.
router.get("/:id/orders", validateRequest(paginationQuerySchema), getCustomerOrderSummary);

// new api: Retrieves transaction-level payment summaries including total lifetime spending, average transaction value, and paid/failed counts.
router.get("/:id/payment-summary", validateRequest(customerIdParamsSchema), getCustomerPaymentSummary);

// new api: Fetches the customer's active cart items (subtotal, quantity) and wishlist product bookmarks.
router.get("/:id/wishlist-cart", validateRequest(customerIdParamsSchema), getCustomerWishlistCart);

// new api: Retrieves a unified chronological activity timeline of auth events, orders, and wishlist additions.
router.get("/:id/timeline", validateRequest(paginationQuerySchema), getCustomerActivityTimeline);

// new api: Fetches login history logs containing IP address, device model, OS version, app version, and security events.
router.get("/:id/login-history", validateRequest(paginationQuerySchema), getCustomerLoginHistory);

// new api: Retrieves Socket.IO support chat overview including total messaging volume, last message text, and unread count.
router.get("/:id/chat-summary", validateRequest(customerIdParamsSchema), getCustomerChatSummary);

// new api: Allows manual administrative override to unlock accounts blocked by brute-force protection.
router.post("/:id/unblock", validateRequest(customerIdParamsSchema), unblockCustomer);

// new api: Fetches internal notes created by admins regarding the customer.
router.get("/:id/notes", validateRequest(paginationQuerySchema), getAdminNotes);

// new api: Creates a new internal administrative note for the customer.
router.post("/:id/notes", validateRequest(addAdminNoteSchema), addAdminNote);

// new api: Updates an existing admin note (restricted to note creator).
router.put("/:id/notes/:noteId", validateRequest(updateAdminNoteSchema), updateAdminNote);

// new api: Deletes an internal admin note.
router.delete("/:id/notes/:noteId", validateRequest(customerNoteParamsSchema), deleteAdminNote);

export default router;
