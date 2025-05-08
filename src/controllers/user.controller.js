import {
  USER_COOKIE_TOKEN_EXPIRY,
  UserLoginType,
  UserRolesEnum,
} from "../constants.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { emailVerificationMailgenContent, sendMail } from "../utils/mail.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import crypto from "crypto";
import { generateAccessAndRefreshTokens } from "../services/token.service.js";

// process.processTicksAndRejections

const registerUser = asyncHandler(async (req, res) => {
  // Retrieves the user info from the request body.
  const { fullname, username, email, password, role } = req.body;

  // Validates the user info.
  if (
    [fullname, username, email, password, role].some(
      filed => filed?.trim() === ""
    )
  ) {
    throw new ApiError(400, "All fields are required");
  }

  if (!(username === username?.toLocaleLowerCase())) {
    throw new ApiError(400, "Username must be lowercase");
  }

  // Check if a user with the provided username or email already exists in the database.
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exists", []);
  }

  // Retrieves the user image from the request file.
  const avatar = req.file;
  const avatarLocalPath = avatar?.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar File is required");
  }

  const cloudinaryAvatar = await uploadOnCloudinary(avatarLocalPath);

  // If the user does not exist, proceed to create a new user
  const user = await User.create({
    avatar: cloudinaryAvatar.url,
    fullname,
    username,
    email,
    password,
    isEmailVerified: false,
    role: role ?? UserRolesEnum.USER,
  });

  // Generate a verification token and its expiry time
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Save the generated verification token and its expiry time in the database
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // Send a verification email to the user with a link to verify their email address
  await sendMail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  // Exclude sensitive fields like password and refreshToken from the response for security purposes
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Respond with a success message indicating that the user was created successfully.
  return res
    .status(201)
    .json(
      new ApiResponse(
        201,
        { user: createdUser },
        "Users registered successfully and verification email has been sent on your email"
      )
    );
});

const loginUser = asyncHandler(async (req, res) => {
  // Retrieves the user information from the request body.
  const { username, email, password } = req.body;

  // Validates the provided user credentials.
  if (!(username || email)) {
    throw new ApiError(400, "Please provide either a username or email", []);
  }

  if (!password) {
    throw new ApiError(400, "Password is required");
  }

  // Checks if the user already exists in the database.
  const user = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (!user) {
    throw new ApiError(404, "User does not exist");
  }

  // Compares the provided password with the hashed password stored in the database.
  const isPassowrdMatch = await user.isPasswordCorrect(password);

  if (!isPassowrdMatch) {
    throw new ApiError(401, "Invalid user credentials");
  }

  // Generates access and refresh tokens for the authenticated user.
  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens({
    username: user.username,
    email: user.email,
    role: user.role,
  });

  user.accessToken = accessToken;
  user.refreshToken = refreshToken;

  await user.save({ validateBeforeSave: false });

  // Retrieves the user document, excluding sensitive fields like password and refreshToken.
  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  // Sends the access token, refresh token, and user information in the response, setting the tokens as HTTP-only cookies.
  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: USER_COOKIE_TOKEN_EXPIRY,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "Logged in successfully"
      )
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  // A logout request is received from an authenticated user
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: undefined, // Clears the refresh token from the database.
      },
    },
    {
      new: true,
    }
  );

  // Clears the `accessToken` and `refreshToken` cookie using the same options.
  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 0,
  };

  // Sends an appropriate response to the client.
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged out"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  // Retrieves the verification token from the request parameters.
  const verificationToken = req.params.verificationToken;

  // Validates the provided token.
  if (!verificationToken) {
    throw new ApiError(400, "Email verification token is missing");
  }

  // Generate a hash from the token that we are receiving
  let hashedToken = crypto
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  // Searches for a user associated with the token and its expiry date.
  const user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) {
    throw new ApiError(489, "Token is invalid or expired");
  }

  // If a user is found, removes the associated email token and expiry date.
  user.emailVerificationToken = undefined;
  user.emailVerificationExpiry = undefined;

  // Marks the user's email as verified by setting `isEmailVerified` to true.
  user.isEmailVerified = true;

  // Saves the updated user information to the database.
  await user.save({ validateBeforeSave: false });

  // Respond with a success message indicating the user's email has been successfully verified
  return res
    .status(200)
    .json(new ApiResponse(200, { isEmailVerified: true }, "Email is verified"));
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  // A resendEmailVerification request is received from an authenticated user
  const user = await User.findOne({ _id: req.user._id });

  // Check if the user's email is already verified
  if (user.isEmailVerified) {
    throw new ApiResponse(400, "User email is already verified");
  }

  // Generate a verification token and its expiry time
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // Save the generated verification token and its expiry time in the database
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // Send a verification email to the user with a link to verify their email address
  await sendMail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  // Respond with a success message indicating that the verification email has been sent successfully.
  return res
    .status(200)
    .json(new ApiResponse(200, "Mail has been sent to your mail ID"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  // refreshAccessToken
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  // forgotPassowrdRequest
});

const resetForgottenPassword = asyncHandler(async (req, res) => {
  // resetForgottenPassword token
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
  // changeCurrentPassword
});

const assignRole = asyncHandler(async (req, res) => {
  // assignRole
});

const getCurrentUser = asyncHandler(async (req, res) => {
  // getCurrentUser
});

const handleSocialLogin = asyncHandler(async (req, res) => {
  const code = req.query.code;
});

const updateUserAvatar = asyncHandler(async (req, res) => {
  // updateUserAvatar
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
