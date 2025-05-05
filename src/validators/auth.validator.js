import { body } from "express-validator";
import { AvailableUserRoles } from "../constants.js";

const userRegisterValidator = () => {
  return [
    body("fullname")
      .trim()
      .notEmpty()
      .withMessage("Fullname is required")
      .isLength({ max: 12 })
      .withMessage("Fullname must be at most 12 characters long"),

    body("username")
      .trim()
      .whitelist("a-z0-9")
      .withMessage("Only lowercase letters and numbers are allowed")
      .notEmpty()
      .withMessage("Username is required")
      .isLowercase()
      .withMessage("Username must be lowercase")
      .isLength({ max: 12 })
      .withMessage("Username must be at most 12 characters long"),

    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isLowercase()
      .withMessage("Email must be lowercase"),

    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isLength({ min: 4, max: 16 })
      .withMessage("Password must be between 4 and 16 characters long"),

    body("role")
      .optional()
      .isUppercase()
      .withMessage("Role must be uppercase")
      .isIn(AvailableUserRoles)
      .withMessage("Invalid user role"),
  ];
};

const userLoginValidator = () => {
  return [
    body("email").optional().isEmail().withMessage("Email is invalid"),
    body("username").optional(),
    body("password").notEmpty().withMessage("Password is required"),
  ];
};

const userChangeCurrentPasswordValidator = () => {
  return [
    body("oldPassword").notEmpty().withMessage("Old Passsword is required"),
    body("newPassword").notEmpty().withMessage("New Password is required"),
  ];
};

const userForgotPasswordValidator = () => {
  return [
    body("email")
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("Email is invalid"),
  ];
};

const userResetPasswordValidator = () => {
  return [body("newPassword").notEmpty().withMessage("Password is required")];
};

const userAssignRoleValidator = () => {
  return [
    body("role")
      .optional()
      .isUppercase()
      .withMessage("Role must be uppercase")
      .isIn(AvailableUserRoles)
      .withMessage("Role is invalid"),
  ];
};

export {
  userRegisterValidator,
  userLoginValidator,
  userChangeCurrentPasswordValidator,
  userForgotPasswordValidator,
  userResetPasswordValidator,
  userAssignRoleValidator,
};
