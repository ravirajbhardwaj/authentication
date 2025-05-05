import { validationResult } from "express-validator";
import { ApiError } from "../utils/apiError.js";

export function validate(req, res, next) {
  const errors = validationResult(req);

  if (errors.isEmpty()) return next();

  const extentendErrors = [];
  errors.array().map(err => extentendErrors.push({ [err.path]: err.msg }));

  throw new ApiError(422, "Received data is not valid", extentendErrors);
}
