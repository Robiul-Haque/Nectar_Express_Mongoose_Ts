import { Router } from "express";
import { authenticate } from "../../middlewares/auth.middleware";
import { validateRequest } from "../../middlewares/validateRequest";
import { createReview, getProductReviews, getSingleReview, updateReview, deleteReview } from "./review.controller";
import { createReviewSchema, updateReviewSchema } from "./review.validation";

const router = Router();

router.post("/create", authenticate(["user", "admin"]), validateRequest(createReviewSchema), createReview);
router.get("/", authenticate(["admin"]), getProductReviews);
// router.get("/:id", authenticate(["admin"]), getSingleReview);
router.patch("/:id", authenticate(["user", "admin"]), validateRequest(updateReviewSchema), updateReview);
router.delete("/:id", authenticate(["user", "admin"]), deleteReview);

export default router;