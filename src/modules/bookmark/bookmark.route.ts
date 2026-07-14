import express from "express";
import validateRequest from "../../middlewares/validateRequest";
import { toggleBookmarkSchema, getBookmarksSchema } from "./bookmark.validation";
import { toggleBookmark, getBookmarks } from "./bookmark.controller";
import authenticate from "../../middlewares/auth.middleware";

const router = express.Router();

router.post("/", authenticate(["user"]), validateRequest(toggleBookmarkSchema), toggleBookmark);
router.get("/", authenticate(["user"]), validateRequest(getBookmarksSchema), getBookmarks);

export default router;