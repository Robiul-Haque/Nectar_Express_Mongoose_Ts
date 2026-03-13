import express from "express";
import { validateRequest } from "../../middlewares/validateRequest";
import { createBookmarkSchema, deleteBookmarkSchema, getBookmarksSchema } from "./bookmark.validation";
import { createBookmark, deleteBookmark, getBookmarks } from "./bookmark.controller";

const router = express.Router();

router.post("/", validateRequest(createBookmarkSchema), createBookmark);
router.delete("/:productId", validateRequest(deleteBookmarkSchema), deleteBookmark);
router.get("/", validateRequest(getBookmarksSchema), getBookmarks);

export default router;