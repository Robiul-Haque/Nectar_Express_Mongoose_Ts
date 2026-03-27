import { Router } from "express";
import authRouter from "../modules/auth/auth.route";
import userRouter from "../modules/user/user.route";
import brandRouter from "../modules/brand/brand.route";
import categoryRoute from "../modules/category/category.route";
import productRoute from "../modules/product/product.route";
import reviewRoute from "../modules/review/review.route";
import bookmarkRoute from "../modules/bookmark/bookmark.route";
import cartRoute from "../modules/cart/cart.router";
import orderRoute from "../modules/order/order.routes";
import paymentRoute from "../modules/payment/payment.route";

const router = Router();

router.use("/auth", authRouter);
router.use("/user", userRouter);
router.use("/brand", brandRouter);
router.use("/category", categoryRoute);
router.use("/product", productRoute);
router.use("/review", reviewRoute);
router.use("/bookmark", bookmarkRoute);
router.use("/cart", cartRoute);
router.use("/order", orderRoute);
router.use("/payment", paymentRoute);

export default router;