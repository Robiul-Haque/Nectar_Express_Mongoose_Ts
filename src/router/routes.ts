import { Router } from "express";
import authRouter from "../modules/auth/auth.route";
import userRouter from "../modules/user/user.route";
import brandRouter from "../modules/brand/brand.route";
import categoryRoute from "../modules/category/category.route";

const router = Router();

router.use("/auth", authRouter);
router.use("/user", userRouter);
router.use("/brand", brandRouter);
router.use("/category", categoryRoute);

export default router;