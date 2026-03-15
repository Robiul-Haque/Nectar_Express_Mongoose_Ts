import { Router } from "express";
import authenticate from "../../middlewares/auth.middleware";
import validateRequest from "../../middlewares/validateRequest";
import { createReview, getProductReviews, updateReview, deleteReview } from "./review.controller";
import { createReviewSchema, deleteReviewSchema, getProductReviewsSchema, updateReviewSchema } from "./review.validation";

const router = Router();

router.post("/create", authenticate(["user"]), validateRequest(createReviewSchema), createReview);
router.get("/", authenticate(["user"]), validateRequest(getProductReviewsSchema), getProductReviews);
// router.get("/:id", authenticate(["admin"]), getSingleReview);
router.patch("/update", authenticate(["user", "admin"]), validateRequest(updateReviewSchema), updateReview);
router.delete("/:id", authenticate(["admin"]), validateRequest(deleteReviewSchema), deleteReview);

export default router;