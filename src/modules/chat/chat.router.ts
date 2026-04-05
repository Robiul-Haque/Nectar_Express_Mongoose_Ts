import express from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createChat, getMyChats } from "./chat.controller";
import { createChatSchema, getChatsQuerySchema } from "./chat.validation";

const router = express.Router();

router.post("/", authenticate(["user", "admin"]), validateRequest(createChatSchema), createChat);
router.get("/", authenticate(["user", "admin"]), validateRequest(getChatsQuerySchema), getMyChats);

export default router;