import express from "express";
import { CreditRequestControllers } from "./creditRequest.controller.js";
import validateRequest from "../../middlewares/validateRequest.js";
import creditRequestValidationSchema from "./creditRequest.validation.js";

const router = express.Router();

router.post('/', validateRequest(creditRequestValidationSchema), CreditRequestControllers.applyCreditRequest);
router.get('/', CreditRequestControllers.getCreditRequest);

export const CreditRequestRoutes = router;