import express, { Request, Response, NextFunction } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import upload from "../../middlewares/upload.middleware";
import { createChat, getMyChats, getChatById, updateChatStatus } from "./chat.controller";
import { createChatSchema, getChatsQuerySchema, chatIdParamSchema, updateChatStatusSchema } from "./chat.validation";
import { getChatMessages, markAsRead, sendMessage } from "../message/message.controller";
import { getMessagesSchema, markAsReadSchema, sendMessageSchema } from "../message/message.validation";

const router = express.Router();

// Helper middleware to adapt params from :id to expected params (e.g. :chatId)
const adaptChatIdParam = (req: Request, res: Response, next: NextFunction) => {
    if (req.params.id && !req.params.chatId) {
        req.params.chatId = req.params.id;
    }
    next();
};

const adaptSendMessageBody = (req: Request, res: Response, next: NextFunction) => {
    if (req.params.id || req.params.chatId) {
        req.body = req.body || {};
        req.body.chatId = req.params.chatId || req.params.id;
    }
    next();
};

router.post("/", authenticate(["user", "admin", "driver"]), validateRequest(createChatSchema), createChat);
router.get("/", authenticate(["user", "admin", "driver"]), validateRequest(getChatsQuerySchema), getMyChats);

// GET /chat/:chatId and /chat/:id
router.get("/:chatId", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(chatIdParamSchema), getChatById);

// Message endpoints on chat router for convenience
router.get("/:chatId/messages", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(getMessagesSchema), getChatMessages);
router.post("/:chatId/messages", authenticate(["user", "admin", "driver"]), upload.single("image"), adaptSendMessageBody, validateRequest(sendMessageSchema), sendMessage);
router.patch("/:chatId/read", authenticate(["user", "admin", "driver"]), adaptChatIdParam, validateRequest(markAsReadSchema), markAsRead);

// PATCH /chat/:chatId, /chat/:chatId/status, /chat/:id, /chat/:id/status (Resolve & Reopen)
router.patch("/:chatId/status", authenticate(["admin"]), adaptChatIdParam, validateRequest(updateChatStatusSchema), updateChatStatus);
router.patch("/:chatId", authenticate(["admin"]), adaptChatIdParam, validateRequest(updateChatStatusSchema), updateChatStatus);

export default router;