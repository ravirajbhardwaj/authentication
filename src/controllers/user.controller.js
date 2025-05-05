import { UserLoginType, UserRolesEnum } from "../constants.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/apiResponse.js";
import { ApiError } from "../utils/apiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { emailVerificationMailgenContent, sendMail } from "../utils/mail.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";

// process.processTicksAndRejections

const registerUser = asyncHandler(async (req, res) => {
  // get data from body
  const { fullname, username, email, password, role } = req.body;

  // validate user data
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

  // check user already in db
  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existedUser) {
    throw new ApiError(409, "User with username or email already exists", []);
  }

  // get data from file for image
  const avatar = req.file;
  const avatarLocalPath = avatar.path;

  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar File is required");
  }

  const cloudinaryAvatar = await uploadOnCloudinary(avatarLocalPath);

  // if not exist then create user
  const user = await User.create({
    avatar: cloudinaryAvatar.url,
    fullname,
    username,
    email,
    password,
    isEmailVerified: false,
    role: role ?? UserRolesEnum.USER,
  });

  // create varification token and tokenExpiry
  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  // saved token in db
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  // send email to user for varification
  await sendMail({
    email: user.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user?.username,
      `${req.protocol}://${req.get("host")}/api/v1/users/verify-email/${unHashedToken}`
    ),
  });

  // exclude password and refreshToken secure fields before sending the response
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  // send respose
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
  // login user
});

const logoutUser = asyncHandler(async (req, res) => {
  // logout user
});

const verifyEmail = asyncHandler(async (req, res) => {
  // verifyEmail token
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  // resendEmailVerification token
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
  // handleSocialLogin
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
