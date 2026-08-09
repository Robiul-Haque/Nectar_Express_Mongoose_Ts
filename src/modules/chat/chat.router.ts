import express from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createChat, getMyChats, getChatById, updateChatStatus } from "./chat.controller";
import { createChatSchema, getChatsQuerySchema, chatIdParamSchema, updateChatStatusSchema } from "./chat.validation";

const router = express.Router();

router.post("/", authenticate(["user", "admin", "driver"]), validateRequest(createChatSchema), createChat);
router.get("/", authenticate(["user", "admin", "driver"]), validateRequest(getChatsQuerySchema), getMyChats);
router.get("/:chatId", authenticate(["user", "admin", "driver"]), validateRequest(chatIdParamSchema), getChatById);
router.patch("/:chatId/status", authenticate(["admin"]), validateRequest(updateChatStatusSchema), updateChatStatus);

export default router;