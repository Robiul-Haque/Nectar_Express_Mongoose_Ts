import express from "express";
import validateRequest from "../../middlewares/validateRequest";
import { createBookmarkSchema, deleteBookmarkSchema, getBookmarksSchema } from "./bookmark.validation";
import { createBookmark, deleteBookmark, getBookmarks } from "./bookmark.controller";
import authenticate from "../../middlewares/auth.middleware";

const router = express.Router();

router.post("/", authenticate(["user"]), validateRequest(createBookmarkSchema), createBookmark);
router.get("/", authenticate(["user", "admin"]), validateRequest(getBookmarksSchema), getBookmarks);
router.delete("/:id", authenticate(["user", "admin"]), validateRequest(deleteBookmarkSchema), deleteBookmark);

export default router;