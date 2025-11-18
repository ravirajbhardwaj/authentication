import { Request, Response } from "express";
import { ApiResponse } from "../utils/apiResponse";
import asyncHandler from "../utils/asyncHandler";

// @ts-ignore
const healthCheck = asyncHandler((req: Request, res: Response) => {
  return res
    .status(200)
    .json(new ApiResponse(200, "OK", "Health check passed"));
});

export { healthCheck };
