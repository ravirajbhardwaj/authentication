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
  assignRole,
} from "../controllers/user.controller";
import { upload } from "../middlewares/multer.middlerware";
import {
  verifyAccessToken,
  verifyPermission,
  verifyRefreshToken,
} from "../middlewares/auth.middlewares";
import { UserRolesEnum } from "../constants";

const router = Router();

// unsecure routes
router
  .route("/register")
  .post(
    upload.single("avatar"),
    registerUser
  );
router.route("/login").post(loginUser);
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
  .post(forgotPasswordRequest);
router
  .route("/reset-password/:resetToken")
  .post(resetForgottenPassword);
router
  .route("/change-password")
  .post(
    verifyAccessToken,
    changeCurrentPassword
  );

router
  .route("/assign-role/:userId")
  .post(
    verifyAccessToken,
    verifyPermission([UserRolesEnum.ADMIN]),
    assignRole
  );

export default router;
