import { Router } from "express";
import authRouter from "../modules/auth/auth.route";
import userRouter from "../modules/user/user.route";
import brandRouter from "../modules/brand/brand.route";
import categoryRoute from "../modules/category/category.route";
import productRoute from "../modules/product/product.route";
import reviewRoute from "../modules/review/review.route";

const router = Router();

router.use("/auth", authRouter);
router.use("/user", userRouter);
router.use("/brand", brandRouter);
router.use("/category", categoryRoute);
router.use("/product", productRoute);
router.use("/review", reviewRoute);

export default router;