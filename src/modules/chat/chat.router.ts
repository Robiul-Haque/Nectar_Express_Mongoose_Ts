import express from "express";
import upload from "../../middlewares/upload.middleware";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { chatIdParamSchema, chatMessageIdParamSchema, sendMessageSchema } from "./chat.validation";
import { sendMessage, getChatMessages, getChatMessagesAdmin, deleteMessageAdmin } from "./chat.controller";

const router = express.Router();

router.post("/send", authenticate(["user", "admin"]), upload.single("image"), validateRequest(sendMessageSchema), sendMessage);
router.get("/:chatId/messages", authenticate(["user", "admin"]), validateRequest(chatIdParamSchema), getChatMessages);

// Admin routes
router.get("/admin/:chatId/messages", authenticate(["admin"]), validateRequest(chatIdParamSchema), getChatMessagesAdmin);
router.delete("/:chatId/message/:messageId", authenticate(["admin"]), validateRequest(chatMessageIdParamSchema), deleteMessageAdmin);

export default router;