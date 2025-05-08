import { Router } from "express";
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  verifyEmail,
  logoutUser,
} from "../controllers/user.controller.js";
import {
  userLoginValidator,
  userRegisterValidator,
} from "../validators/auth.validator.js";
import { validate } from "../validators/validate.js";
import { upload } from "../middlewares/multer.middlerware.js";
import { verifyAccessToken } from "../middlewares/auth.middlewares.js";

const router = Router();

// unsecure routes
router
  .route("/register")
  .post(
    upload.single("avatar"),
    userRegisterValidator(),
    validate,
    registerUser
  );
router.route("/login").post(userLoginValidator(), validate, loginUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/verify-email/:verificationToken").get(verifyEmail);

router.route("/logout").post(verifyAccessToken, logoutUser)

export default router;
