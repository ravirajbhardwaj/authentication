import { Router } from "express";
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  verifyEmail,
} from "../controllers/user.controller.js";

const router = Router();

// unsecure routes
router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/verify-email/:verificationToken").get(verifyEmail);

export default router;
