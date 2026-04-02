import express from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createOrGetChat, getMyChats } from "./chat.controller";
import { createChatSchema, getChatsQuerySchema } from "./chat.validation";

const router = express.Router();

router.post("/", authenticate, validateRequest(createChatSchema), createOrGetChat);
router.get("/", authenticate, validateRequest(getChatsQuerySchema), getMyChats);``

export default router;