import express, { Request, Response, NextFunction } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import upload from "../../middlewares/upload.middleware";
import { createChat, getMyChats, getChatById, updateChatStatus } from "./chat.controller";
import { createChatSchema, getChatsQuerySchema, chatIdParamSchema, updateChatStatusSchema } from "./chat.validation";
import { deleteMessageAdmin, getChatMessages, markAsRead, sendMessage } from "../message/message.controller";
import { getMessagesSchema, markAsReadSchema, sendMessageSchema } from "../message/message.validation";

const router = express.Router();

// Helper middleware to adapt params from :id to expected params (e.g. :chatId)
const adaptChatIdParam = (req: Request, res: Response, next: NextFunction) => {
    if (req.params.id) {
        req.params.chatId = req.params.id;
    }
    next();
};

const adaptSendMessageBody = (req: Request, res: Response, next: NextFunction) => {
    if (req.params.id) {
        req.body = req.body || {};
        req.body.chatId = req.params.id;
    }
    next();
};

// GET /api/v1/support/conversations
router.get("/", authenticate(["user", "admin", "driver"]), validateRequest(getChatsQuerySchema), getMyChats);

// POST /api/v1/support/conversations
router.post("/", authenticate(["user", "admin", "driver"]), validateRequest(createChatSchema), createChat);

// GET /api/v1/support/conversations/:id
router.get("/:id", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(chatIdParamSchema), getChatById);

// GET /api/v1/support/conversations/:id/messages
router.get("/:id/messages", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(getMessagesSchema), getChatMessages);

// POST /api/v1/support/conversations/:id/messages
router.post("/:id/messages", authenticate(["user", "admin", "driver"]), upload.single("image"), adaptSendMessageBody, validateRequest(sendMessageSchema), sendMessage);

// PATCH /api/v1/support/conversations/:id/read
router.patch("/:id/read", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(markAsReadSchema), markAsRead);

// PATCH /api/v1/support/conversations/:id/status
router.patch("/:id/status", authenticate(["admin"]), adaptChatIdParam, validateRequest(updateChatStatusSchema), updateChatStatus);

export default router;
