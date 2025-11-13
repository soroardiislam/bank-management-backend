import express from "express";
import { ProfileControllers } from "./profile.controller.js";
import validateRequest from "../../middlewares/validateRequest.js";
import profileValidationSchema from "./profile.validation.js";

const router = express.Router();

router.patch("/:userId", validateRequest(profileValidationSchema), ProfileControllers.updateProfile);
router.get("/:userId", ProfileControllers.getProfile);

export const ProfileRoutes = router;