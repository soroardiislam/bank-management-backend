import express from "express";
import { UserControllers } from "./user.controller.js";
import validateRequest from "../../middlewares/validateRequest.js";
import { userValidationSchema } from "./user.validation.js";

const router = express.Router();

router.post("/sign-up", validateRequest(userValidationSchema.createUserValidationSchema), UserControllers.createUser);
router.post("/sign-in", validateRequest(userValidationSchema.userSignInValidationSchema), UserControllers.loginUser);
router.patch("/security", UserControllers.updatePassword);
router.post("/forgot-password", UserControllers.sendOtp);
router.post("/verify-otp", UserControllers.verifyOtp);
router.post("/reset-password", UserControllers.resetPassword);


export const UserRoutes = router;