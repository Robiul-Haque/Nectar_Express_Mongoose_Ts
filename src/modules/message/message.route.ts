import express from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import upload from "../../middlewares/upload.middleware";
import { deleteMessageSchema, getMessagesSchema, markAsReadSchema, sendMessageSchema } from "./message.validation";
import { deleteMessageAdmin, getChatMessages, markAsRead, sendMessage } from "./message.controller";

const router = express.Router();

router.post("/send", authenticate(["user", "admin", "driver"]), upload.single("image"), validateRequest(sendMessageSchema), sendMessage);
router.get("/:chatId", authenticate(["user", "admin", "driver"]), validateRequest(getMessagesSchema), getChatMessages);
router.patch("/read/:chatId", authenticate(["user", "admin", "driver"]), validateRequest(markAsReadSchema), markAsRead);
router.delete("/:messageId", authenticate(["admin"]), validateRequest(deleteMessageSchema), deleteMessageAdmin);

export default router;