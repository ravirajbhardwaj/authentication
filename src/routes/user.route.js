import { Router } from "express";
import {
  registerUser,
  loginUser,
  refreshAccessToken,
  verifyEmail,
  logoutUser,
  resendEmailVerification,
  getCurrentUser,
  updateUserAvatar,
  changeCurrentPassword,
  forgotPasswordRequest,
  resetForgottenPassword,
} from "../controllers/user.controller.js";
import {
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userLoginValidator,
  userRegisterValidator,
  userResetPasswordValidator,
} from "../validators/auth.validator.js";
import { validate } from "../validators/validate.js";
import { upload } from "../middlewares/multer.middlerware.js";
import {
  verifyAccessToken,
  verifyRefreshToken,
} from "../middlewares/auth.middlewares.js";

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
router.route("/verify-email/:verificationToken").get(verifyEmail);

// secure routes
router.route("/logout").post(verifyAccessToken, logoutUser);
router
  .route("/resend-email-verification")
  .post(verifyAccessToken, resendEmailVerification);

router.route("/current-user").get(verifyAccessToken, getCurrentUser);
router.route("/refresh-token").post(verifyRefreshToken, refreshAccessToken);
router
  .route("/avatar")
  .patch(verifyAccessToken, upload.single("avatar"), updateUserAvatar);

router
  .route("/forgot-password")
  .post(userForgotPasswordValidator(), validate, forgotPasswordRequest);
router
  .route("/reset-password/:resetToken")
  .post(userResetPasswordValidator(), validate, resetForgottenPassword);
router
  .route("/change-password")
  .post(
    verifyAccessToken,
    userChangeCurrentPasswordValidator(),
    validate,
    changeCurrentPassword
  );

export default router;
