import express from "express";
import validateRequest from "../../middlewares/validateRequest";
import { toggleBookmarkSchema, getBookmarksSchema, checkBookmarkSchema } from "./bookmark.validation";
import { toggleBookmark, getBookmarks, checkBookmarkStatus } from "./bookmark.controller";
import authenticate from "../../middlewares/auth.middleware";

const router = express.Router();

router.post("/", authenticate(["user"]), validateRequest(toggleBookmarkSchema), toggleBookmark);
router.get("/", authenticate(["user"]), validateRequest(getBookmarksSchema), getBookmarks);
router.get("/check/:productId", authenticate(["user"]), validateRequest(checkBookmarkSchema), checkBookmarkStatus);

export default router;