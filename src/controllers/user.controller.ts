import { CookieOptions, Request, Response } from "express";
import {
  USER_COOKIE_TOKEN_EXPIRY,
  UserLoginType,
  UserRolesEnum,
} from "../constants";
import { ApiResponse } from "../utils/apiResponse";
import { ApiError } from "../utils/apiError";
import asyncHandler from "../utils/asyncHandler";

import {
  emailVerificationMailgenContent,
  forgotPasswordMailgenContent,
  sendMail,
} from "../utils/mail.js";
import { uploadOnCloudinary } from "../utils/cloudinary";
import { generateAccessAndRefreshTokens } from "../services/token.service";
import { createHash, generateTemporaryToken, hashPassword, passwordMatch } from "../utils/helper";
import { logger } from "../logger/pino.logger";

import { prisma } from "../db/database"
import { User } from "../generated/prisma/client";
import { handleZodError } from "../validators/handleZodError";
import { validateChangePassword, validateEmail, validateLogin, validateRegister, validateResetPassword } from "../validators/auth.validator";

export const sanitizeUser = (user: User) => {
  const {
    password,
    emailVerificationToken,
    emailVerificationExpiry,
    forgotPasswordToken,
    forgotPasswordExpiry,
    createdAt,
    updatedAt,
    ...safeUser
  } = user;
  return safeUser;
};

const registerUser = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the user info from the request body.
  const { fullname, username, email, password, role } = handleZodError(validateRegister(req.body));
  logger.info(`Registration attempt: EMAIL: ${email}, IP: ${req.ip}`);

  // Check if a user with the provided email already exists in the database.
  const existedUser = await prisma.user.findUnique({ where: { email } });

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exists");
  }

  let avatarUrl;
  if (req.file) {
    try {
      const uploaded = await uploadOnCloudinary(req.file.path);
      avatarUrl = uploaded?.secure_url;
      logger.info(`Avatar uploaded successfully: EMAIL: ${email}, URL: ${avatarUrl}`);
    } catch (err: any) {
      logger.warn(`Avatar upload failed for ${email} due to ${err.message}`);
    }
  }

  // Generate a verification token and its expiry time and HashPassword
  const hashedPassword = await hashPassword(password);
  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken();

  // If the user does not exist, create a new user
  const user = await prisma.user.create({
    data: {
      avatar: avatarUrl,
      fullname,
      username,
      email,
      password: hashedPassword,
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: tokenExpiry,
      isEmailVerified: false,
      role: role ?? UserRolesEnum.USER,
    },
  });

  // Send a verification email to the user with a link to verify their email address
  await sendMail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  logger.info(`Verification email sent - Email: ${email}, UserID: ${user.id}, IP: ${req.ip}`);
  logger.info(`User registered successfully - Email: ${email}, UserID: ${user.id}, IP: ${req.ip}`);

  const safeUser = sanitizeUser(user);

  // Respond with a success message indicating that the user was created successfully.
  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { user: safeUser },
        "Users registered successfully and verification email has been sent on your email"
      )
    );
});

const loginUser = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the user information from the request body.
  const { email, password } = handleZodError(validateLogin(req.body));
  logger.info(`Login attempt: EMAIL: ${email}, IP: ${req.ip}`);

  // Checks if the user already exists in the database.
  const user = await prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      username: true,
      password: true,
      role: true,
      loginType: true,
      isEmailVerified: true,
      avatar: true,
      fullname: true,
    }
  });

  if (!user) {
    logger.warn(`Login failed - User not found: ${email}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  // Check if email is verified
  if (!user.isEmailVerified) {
    logger.warn(`Login failed - Email not verified: ${email}, IP: ${req.ip}`);
    throw new ApiError(403, "Please verify your email before logging in");
  }

  // Check login type compatibility
  if (user.loginType !== UserLoginType.EMAIL) {
    logger.warn(`Login failed - Wrong login type: ${email}, Type: ${user.loginType}, IP: ${req.ip}`);
    throw new ApiError(
      400,
      `You have previously registered using ${user.loginType?.toLowerCase()}. 
      Please use the ${user.loginType?.toLowerCase()} login option to access your account.`
    );
  }

  // Compares the provided password with the hashed password stored in the database.
  const isPassowrdMatch = await passwordMatch(password, user.password as string);

  if (!isPassowrdMatch) {
    throw new ApiError(401, "Invalid user credentials");
  }

  // Generate access and refresh tokens
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens({
    _id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
  });

  // Update refresh token in database
  await prisma.user.update({
    where: { id: user.id },
    data: { refreshToken },
  });

  // Sanitize user data before sending
  const safeUser = sanitizeUser(user as User);

  logger.info(`User logged in successfully - Email: ${email}, UserID: ${user.id}, IP: ${req.ip}`);

  // Set cookie options
  const cookieOptions: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Only secure in production
    sameSite: "strict",
    maxAge: USER_COOKIE_TOKEN_EXPIRY,
  };

  // Send response with tokens and user data
  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { user: safeUser, accessToken, refreshToken },
        "Logged in successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req: Request, res: Response) => {
  // A logout request is received from an authenticated user
  await prisma.user.update({
    where: { id: (req as any).user._id },
    data: {
      refreshToken: undefined,
    },
  });

  // Clears the `accessToken` and `refreshToken` cookie using the same options.
  const cookieOptions: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Only secure in production
    sameSite: "strict",
    maxAge: 0,
  };

  // Sends an appropriate response to the client.
  return res
    .status(200)
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const verifyEmail = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the verification token from the request parameters.
  const verificationToken = req.params.verificationToken;
  logger.info(`Email verification attempt, IP: ${req.ip}`);

  // Validates the provided token.
  if (!verificationToken) {
    logger.warn(`Email verification failed - Missing token, IP: ${req.ip}`);
    throw new ApiError(400, "Email verification token is missing");
  }

  // Generate a hash from the token that we are receiving
  const hashedToken = createHash(verificationToken);

  // Searches for a user associated with the token and its expiry date.
  const user = await prisma.user.findFirst({
    where: {
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: {
        gt: new Date(),
      },
    },
    select: {
      id: true,
      email: true,
      username: true,
      isEmailVerified: true,
    },
  });

  // Handle invalid or expired token
  if (!user) {
    logger.warn(`Email verification failed - Invalid or expired token, IP: ${req.ip}`);
    throw new ApiError(400, "Invalid or expired verification token");
  }

  // Check if email is already verified
  if (user.isEmailVerified) {
    logger.info(`Email already verified - Email: ${user.email}, UserID: ${user.id}`);
    return res
      .status(200)
      .json(
        new ApiResponse(200, { isEmailVerified: true }, "Email is already verified")
      );
  }

  // Update user record - mark email as verified and clear verification tokens
  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerificationToken: null,
      emailVerificationExpiry: null,
      isEmailVerified: true,
    },
  });

  logger.info(`Email verified successfully - Email: ${user.email}, UserID: ${user.id}, IP: ${req.ip}`);


  // Respond with success message
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { isEmailVerified: true },
        "Email verified successfully! You can now log in to your account."
      )
    );
});

const resendEmailVerification = asyncHandler(async (req: Request, res: Response) => {
  // A resendEmailVerification request is received from an authenticated user'
  const userId = (req as any).user._id;
  logger.info(`Resend email verification attempt - UserID: ${userId}, IP: ${req.ip}`);

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      username: true,
      isEmailVerified: true,
    },
  });

  // Check if the user exist
  if (!user) {
    logger.warn(`Resend verification failed - User not found: USERID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  // Check if the user's email is already verified
  if ((user as User).isEmailVerified) {
    logger.info(`Resend verification aborted - Email already verified: ${user.email}, UserID: ${user.id}`);
    throw new ApiError(400, "User email is already verified");
  }

  // Generate a verification token and its expiry time
  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken();

  // Save the generated verification token and its expiry time in the database
  await prisma.user.update({
    where: { id: user.id },
    data: {
      emailVerificationToken: hashedToken,
      emailVerificationExpiry: tokenExpiry,
    },
  });

  // Send a verification email to the user with a link to verify their email address
  await sendMail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  logger.info(`Verification email resent - Email: ${user.email}, UserID: ${user.id}, IP: ${req.ip}`);

  // Respond with a success message indicating that the verification email has been sent successfully.
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Mail has been sent to your mail ID"));
});

const refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the authenticated user from the request
  const userId = (req as any).user._id;
  logger.info(`Refresh access token attempt - UserID: ${userId}, IP: ${req.ip}`);

  // Fetch fresh user data from DB
  const dbUser = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      username: true,
      role: true,
    },
  });

  if (!dbUser) {
    logger.warn(`Refresh token failed - User not found: UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  // Generates new access and refresh tokens for the user
  const { accessToken, refreshToken: newRefreshToken } = await generateAccessAndRefreshTokens({
    _id: dbUser.id,
    username: dbUser.username,
    email: dbUser.email,
    role: dbUser.role,
  });


  // Updates the user's refresh token in the database
  await prisma.user.update({
    where: { id: dbUser.id },
    data: { refreshToken: newRefreshToken },
  });

  logger.info(`Access & refresh tokens refreshed - UserID: ${dbUser.id}, IP: ${req.ip}`);

  // Set cookie options
  const cookieOptions: CookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production", // Only secure in production
    sameSite: "strict",
    maxAge: USER_COOKIE_TOKEN_EXPIRY,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", newRefreshToken, cookieOptions)
    .json(
      new ApiResponse(
        200,
        { accessToken, newRefreshToken },
        "Access token refreshed"
      )
    );
});

const forgotPasswordRequest = asyncHandler(async (req: Request, res: Response) => {
  // get email from body
  const { email } = handleZodError(validateEmail(req.body));
  logger.info(`Forgot password request received - Email: ${email}, IP: ${req.ip}`);

  // validate email and check email exist in db
  if (!email) {
    logger.warn(`Forgot password failed - Missing email, IP: ${req.ip}`);
    throw new ApiError(400, "Email is required");
  }

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    logger.warn(`Forgot password failed - User not found for email: ${email}, IP: ${req.ip}`);
    throw new ApiError(422, "User does not exist");
  }

  // Generate forgot and reset password token and expiry
  const { unHashedToken, hashedToken, tokenExpiry } = generateTemporaryToken();

  await prisma.user.update({
    where: { id: user.id },
    data: {
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: tokenExpiry,
    },
  });

  // Send a verification email to the user with a link to verify their email address
  sendMail({
    email: user.email,
    subject: "Forgot Password request",
    mailgenContent: forgotPasswordMailgenContent(
      user?.username,
      `${process.env.FORGOT_PASSWORD_REDIRECT_URL}/${unHashedToken}`
    ),
  });

  logger.info(`Forgot password email sent - Email: ${user.email}, UserID: ${user.id}, IP: ${req.ip}`);

  // Respond with a success message indicating that the verification email has been sent successfully.
  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Mail has been sent to your mail ID"));
});

const resetForgottenPassword = asyncHandler(async (req: Request, res: Response) => {
  // exterct refresh Token from params and get newPasswrod from req body
  const resetToken = req.params.resetToken;
  const { password } = handleZodError(validateResetPassword(req.body));

  logger.info(`Reset forgotten password attempt - IP: ${req.ip}`);

  // validate resetToken and newPassword
  if (!resetToken && !password) {
    logger.warn(`Reset password failed - Missing token or password, IP: ${req.ip}`);
    throw new ApiError(400, "Invalid reset token and new Password");
  }

  // Generate a hash from the token that we are receiving
  let hashedToken = createHash((resetToken as string))

  // check token is valid or not expire
  const user = await prisma.user.findFirst({
    where: {
      forgotPasswordToken: hashedToken,
      forgotPasswordExpiry: {
        gt: new Date(),
      },
    },
    select: {
      id: true,
    },
  });

  if (!user) {
    logger.warn(`Reset password failed - Token invalid or expired, IP: ${req.ip}`);
    throw new ApiError(489, "Token is invalid or expired");
  }

  // If a user is found create new hashedPassword, removes the associated forgot password token and expiry date
  const hashedPassword = await hashPassword(password);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      password: hashedPassword,
      forgotPasswordToken: null,
      forgotPasswordExpiry: null,
    },
  });

  logger.info(`Password reset successfully - UserID: ${user.id}, IP: ${req.ip}`);

  // send success status
  return res
    .status(200)
    .json(new ApiResponse(201, {}, "Password reset successfully"));
});

const changeCurrentPassword = asyncHandler(async (req: Request, res: Response) => {
  // get data from request body
  const { currentPassword, newPassword } = handleZodError(validateChangePassword(req.body));
  const userId = (req as any).user._id;

  logger.info(`Change password attempt - UserID: ${userId}, IP: ${req.ip}`);

  // Validates the provided user old and new Password.
  if (!currentPassword || !newPassword) {
    logger.warn(`Change password failed - Missing fields - UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(400, "Current Password and New Password is required");
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, password: true },
  });

  if (!user) {
    logger.warn(`Change password failed - User not found - UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  // Compares the old password with the hashed password stored in the database.
  const isPassowrdMatch = passwordMatch(currentPassword, user.password);

  if (!isPassowrdMatch) {
    logger.warn(`Change password failed - Invalid current password - UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(400, "Invalid current password");
  }

  // update user password to newPassword and save
  const hashedNewPassword = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: user.id },
    data: { password: hashedNewPassword },
  });

  logger.info(`Password changed successfully - UserID: ${user.id}, IP: ${req.ip}`);

  // send success status your password is changed
  return res
    .status(200)
    .json(new ApiResponse(201, {}, "Password changed successfully"));
});

const assignRole = asyncHandler(async (req: Request, res: Response) => {
  // get userId from params and role from body
  const userId = req.params.userId;
  const { role } = req.body;
  const performedBy = (req as any).user?._id;

  logger.info(`Assign role attempt - TargetUserID: ${userId}, NewRole: ${role}, PerformedBy: ${performedBy}, IP: ${req.ip}`);

  // find user
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    logger.warn(`Assign role failed - User not found - TargetUserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  await prisma.user.update({
    where: { id: userId },
    data: { role },
  });

  logger.info(`Role updated for user - TargetUserID: ${userId}, NewRole: ${role}, PerformedBy: ${performedBy}, IP: ${req.ip}`);

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Role changed for the user"));
});

const getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the currently authenticated user's information from the request object.
  const userId = (req as any).user._id;
  logger.info(`Get current user request - UserID: ${userId}, IP: ${req.ip}`);

  const user = await prisma.user.findUnique({
    where: {
      id: userId
    },
    select: {
      id: true,
      email: true,
      username: true,
      fullname: true,
      avatar: true,
      role: true,
      loginType: true,
      isEmailVerified: true,
      createdAt: true,
      updatedAt: true,
    },
  })

  if (!user) {
    logger.warn(`Get current user failed - User not found - UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(404, "User does not exist");
  }

  logger.info(`Current user fetched successfully - UserID: ${userId}, IP: ${req.ip}`);

  // The `req.user` is populated by the authentication middleware after verifying the user's token.
  return res
    .status(200)
    .json(new ApiResponse(200, { user }, "Current user fetched successfully"));
});

const updateUserAvatar = asyncHandler(async (req: Request, res: Response) => {
  // Retrieves the user image from the request file.
  const avatar = req.file;
  const avatarLocalPath = avatar?.path;
  const userId = (req as any).user._id;
  logger.info(`Update avatar attempt - UserID: ${userId}, IP: ${req.ip}`);

  if (!avatarLocalPath) {
    logger.warn(`Update avatar failed - Missing file - UserID: ${userId}, IP: ${req.ip}`);
    throw new ApiError(400, "Avatar image is required");
  }

  const cloudinaryAvatar = await uploadOnCloudinary(avatarLocalPath);
  const avatarUrl = cloudinaryAvatar?.secure_url ?? cloudinaryAvatar?.url;

  const updatedUser = await prisma.user.update({
    where: { id: userId },
    data: { avatar: avatarUrl },
    select: {
      id: true,
      email: true,
      username: true,
      fullname: true,
      avatar: true,
      role: true,
      isEmailVerified: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  logger.info(`Avatar updated successfully - UserID: ${userId}, AvatarURL: ${avatarUrl}, IP: ${req.ip}`);
  return res
    .status(201)
    .json(new ApiResponse(
      200, { user: updatedUser },
      "Avatar updated successfully"
    ));
});

const handleSocialLogin = asyncHandler(async (req: Request, res: Response) => {
  //
});

export {
  assignRole,
  changeCurrentPassword,
  forgotPasswordRequest,
  resetForgottenPassword,
  getCurrentUser,
  handleSocialLogin,
  loginUser,
  logoutUser,
  refreshAccessToken,
  registerUser,
  resendEmailVerification,
  updateUserAvatar,
  verifyEmail,
};
